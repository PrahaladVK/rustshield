// scanner.rs — detection pipeline with exception check as layer 0

use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use crate::db::SignatureDb;
use crate::yara_scanner::YaraEngine;

const ENTROPY_THRESHOLD:         f64   = 7.4;
const HIGH_ENTROPY_SECTION_RATIO:f64   = 0.30;
const MIN_PE_BYTES:              usize = 4_096;
const MAX_PE_BYTES:              usize = 64 * 1024 * 1024;
const PE_EXTS:   &[&str] = &["exe","dll","scr","sys","drv","cpl","ocx","com"];
const TRUSTED_PREFIXES: &[&str] = &[
    "C:\\WINDOWS\\SYSTEM32\\","C:\\WINDOWS\\SYSWOW64\\","C:\\WINDOWS\\WINSXS\\",
    "C:\\PROGRAM FILES\\","C:\\PROGRAM FILES (X86)\\","C:\\PROGRAMDATA\\MICROSOFT\\",
    "C:\\WINDOWS\\SERVICING\\",
];
const PACKER_SECTION_NAMES: &[&str] = &[
    "UPX0","UPX1","UPX2",".MPRESS1",".MPRESS2",".pack",".perplex",
    "PEBundle","PECompact",".aspack",".adata","RLPack",
];

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict { Clean, Suspicious(String), Malicious(String) }

pub struct ScanResult {
    pub path:    String,
    pub sha256:  String,
    pub verdict: Verdict,
}

struct PeSection { name:String, entropy:f64, is_executable:bool, is_writable:bool }

pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop { let n=file.read(&mut buf)?; if n==0{break;} hasher.update(&buf[..n]); }
    Ok(format!("{:x}", hasher.finalize()))
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut c=[0u64;256]; for &b in data { c[b as usize]+=1; }
    let l=data.len() as f64;
    c.iter().filter(|&&x|x>0).map(|&x|{ let p=x as f64/l; -p*p.log2() }).sum()
}

fn parse_pe_sections(data: &[u8]) -> Vec<PeSection> {
    let mut out=Vec::new();
    if data.len()<64 || &data[0..2]!=b"MZ" { return out; }
    let pe_off=u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0;4])) as usize;
    if pe_off+24>data.len() || &data[pe_off..pe_off+4]!=b"PE\0\0" { return out; }
    let num=u16::from_le_bytes([data[pe_off+6],data[pe_off+7]]) as usize;
    let opt=u16::from_le_bytes([data[pe_off+20],data[pe_off+21]]) as usize;
    if num>96 { return out; }
    let sec=pe_off+24+opt;
    for i in 0..num {
        let s=sec+i*40; if s+40>data.len() { break; }
        let name=String::from_utf8_lossy(&data[s..s+8]).trim_matches('\0').to_string();
        let raw_size=u32::from_le_bytes(data[s+16..s+20].try_into().unwrap_or([0;4])) as usize;
        let raw_off =u32::from_le_bytes(data[s+20..s+24].try_into().unwrap_or([0;4])) as usize;
        let chars   =u32::from_le_bytes(data[s+36..s+40].try_into().unwrap_or([0;4]));
        if raw_size==0||raw_off==0||raw_off>=data.len() { continue; }
        let end=(raw_off+raw_size).min(data.len());
        out.push(PeSection { name, entropy:shannon_entropy(&data[raw_off..end]),
                              is_executable:(chars&0x2000_0000)!=0, is_writable:(chars&0x8000_0000)!=0 });
    }
    out
}

fn run_heuristics(sections: &[PeSection]) -> (u8, Vec<String>) {
    let mut score=0u8; let mut reasons=Vec::new();
    if sections.is_empty() { return (0,reasons); }
    let cands: Vec<&PeSection>=sections.iter()
        .filter(|s|!s.name.eq_ignore_ascii_case(".rsrc")&&!s.name.eq_ignore_ascii_case(".data"))
        .collect();
    let hi: Vec<&&PeSection>=cands.iter().filter(|s|s.entropy>=ENTROPY_THRESHOLD).collect();
    if !cands.is_empty() {
        let ratio=hi.len() as f64/cands.len() as f64;
        if ratio>=HIGH_ENTROPY_SECTION_RATIO&&!hi.is_empty() {
            reasons.push(format!("High-entropy sections ({:.0}% > {:.1} bits): {}",
                ratio*100.0,ENTROPY_THRESHOLD,hi.iter().map(|s|s.name.as_str()).collect::<Vec<_>>().join(",")));
            score+=2;
        }
    }
    let wx: Vec<&PeSection>=sections.iter().filter(|s|s.is_executable&&s.is_writable).collect();
    if !wx.is_empty() {
        reasons.push(format!("Writable+executable sections: {}",wx.iter().map(|s|s.name.as_str()).collect::<Vec<_>>().join(",")));
        score+=2;
    }
    let pk: Vec<&str>=sections.iter().filter_map(|s|
        PACKER_SECTION_NAMES.iter().find(|&&p|s.name.eq_ignore_ascii_case(p)).map(|_|s.name.as_str())
    ).collect();
    if !pk.is_empty() { reasons.push(format!("Known packer section names: {}",pk.join(","))); score+=1; }
    let non_empty=sections.iter().filter(|s|s.entropy>0.5).count();
    if non_empty<=1&&sections.len()<=2 { reasons.push("Very few PE sections — possibly a packed stub".into()); score+=1; }
    (score,reasons)
}

fn heuristic_verdict(path: &Path) -> Verdict {
    let ext=path.extension().and_then(|e|e.to_str()).map(|e|e.to_lowercase()).unwrap_or_default();
    if !PE_EXTS.contains(&ext.as_str()) { return Verdict::Clean; }
    let pu=path.to_string_lossy().to_uppercase();
    if TRUSTED_PREFIXES.iter().any(|p|pu.starts_with(*p)) { return Verdict::Clean; }
    let size=path.metadata().map(|m|m.len()).unwrap_or(0) as usize;
    if size<MIN_PE_BYTES||size>MAX_PE_BYTES { return Verdict::Clean; }
    let data=match fs::read(path) { Ok(d)=>d, Err(_)=>return Verdict::Clean };
    let sections=parse_pe_sections(&data);
    if sections.is_empty() { return Verdict::Clean; }
    let (score,reasons)=run_heuristics(&sections);
    if score>=2 { Verdict::Suspicious(reasons.join(" | ")) } else { Verdict::Clean }
}

pub fn scan_file(path: &Path, db: &Arc<SignatureDb>, yara: &Arc<YaraEngine>) -> io::Result<ScanResult> {
    let path_str = path.to_string_lossy().to_string();

    // Layer 0: exception check by path (no hashing needed — fast)
    if db.is_path_excepted(&path_str).unwrap_or(false) {
        log::debug!("Excepted (path): {}", path_str);
        return Ok(ScanResult { path: path_str, sha256: String::new(), verdict: Verdict::Clean });
    }

    let sha256 = hash_file(path)?;

    // Layer 0b: exception check by hash
    if db.is_hash_excepted(&sha256).unwrap_or(false) {
        log::debug!("Excepted (hash): {}", path_str);
        return Ok(ScanResult { path: path_str, sha256, verdict: Verdict::Clean });
    }

    // Layer 1: hash signature DB
    if let Ok(Some((threat_name,_)))=db.lookup(&sha256) {
        return Ok(ScanResult { path:path_str, sha256, verdict:Verdict::Malicious(threat_name) });
    }

    // Layer 2: YARA
    let hits=yara.scan_file(path);
    if !hits.is_empty() {
        return Ok(ScanResult { path:path_str, sha256, verdict:Verdict::Malicious(format!("YARA:{}",hits.join(","))) });
    }

    // Layer 3: PE heuristics
    Ok(ScanResult { path:path_str, sha256, verdict:heuristic_verdict(path) })
}
