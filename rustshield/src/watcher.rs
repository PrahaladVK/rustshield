use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::{mpsc::{channel,Receiver},Arc};
use crate::db::SignatureDb;
use crate::quarantine;
use crate::scanner::{scan_file,Verdict};
use crate::yara_scanner::YaraEngine;

pub fn resolve_watch_paths() -> Vec<String> {
    let profile=std::env::var("USERPROFILE").unwrap_or_else(|_|"C:\\Users\\Public".to_string());
    let temp=std::env::var("TEMP").or_else(|_|std::env::var("TMP")).unwrap_or_else(|_|format!("{}\\AppData\\Local\\Temp",profile));
    let candidates=vec![
        format!("{}\\Downloads",profile), format!("{}\\Desktop",profile),
        format!("{}\\Documents",profile), temp,
        format!("{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",profile),
        "C:\\Users\\Public\\Downloads".to_string(), "C:\\ProgramData".to_string(),
    ];
    candidates.into_iter().filter(|p|Path::new(p).exists()).collect()
}

pub fn watch_paths(paths: &[String], db: Arc<SignatureDb>, yara: Arc<YaraEngine>) -> notify::Result<()> {
    let (tx,rx): (_,Receiver<notify::Result<Event>>)=channel();
    let mut watcher: RecommendedWatcher=notify::recommended_watcher(tx)?;
    for p in paths {
        match watcher.watch(Path::new(p),RecursiveMode::Recursive) {
            Ok(_)=>log::info!("Watching: {}",p),
            Err(e)=>log::warn!("Could not watch {}: {:?}",p,e),
        }
    }
    for res in rx { match res { Ok(e)=>handle_event(e,&db,&yara), Err(e)=>log::warn!("Watch error: {:?}",e) } }
    Ok(())
}

fn handle_event(event: Event, db: &Arc<SignatureDb>, yara: &Arc<YaraEngine>) {
    if !matches!(event.kind, EventKind::Create(_)|EventKind::Modify(_)) { return; }
    for path in event.paths {
        if !path.is_file() { continue; }
        let fname=path.file_name().map(|n|n.to_string_lossy().to_string()).unwrap_or_default();
        match scan_file(&path,db,yara) {
            Ok(result) => {
                let vs=match &result.verdict { Verdict::Clean=>"clean",Verdict::Suspicious(_)=>"suspicious",Verdict::Malicious(_)=>"malicious" };
                let _=db.log_scan(&result.path,&result.sha256,vs);
                match &result.verdict {
                    Verdict::Malicious(name) => {
                        log::warn!("THREAT  [{}]  {}  →  {}",&result.sha256[..8],name,result.path);
                        if let Err(e)=quarantine::quarantine_file(&path,db,&result.sha256,name) {
                            log::error!("Quarantine failed for {}: {:?}",fname,e);
                        }
                    }
                    Verdict::Suspicious(reason) => log::warn!("SUSPECT [{}]  {}  →  {}",&result.sha256[..8],reason,result.path),
                    Verdict::Clean => log::debug!("Clean: {}",fname),
                }
            }
            Err(e) => log::debug!("skip {:?}: {:?}",path,e),
        }
    }
}
