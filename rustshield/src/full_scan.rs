// full_scan.rs — directory + individual-file scanning with phase tracking

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use walkdir::WalkDir;
use serde::Serialize;

use crate::db::SignatureDb;
use crate::quarantine;
use crate::scanner::{scan_file, Verdict};
use crate::yara_scanner::YaraEngine;


/// Returns all Windows drive letters that exist on this machine (A:\ → Z:\).
pub fn detect_drives() -> Vec<String> {
    (b'A'..=b'Z')
        .map(|c| format!("{}:\\", c as char))
        .filter(|p| std::path::Path::new(p).exists())
        .collect()
}

// ── Progress (shared with API polling) ────────────────────────────────

#[derive(Default, Clone, Serialize)]
pub struct ScanProgress {
    pub active:             bool,
    pub cancelled:          bool,
    /// "dirs" during directory walk, "processes" during running-exe scan
    pub phase:              String,
    pub current_file:       String,
    pub current_root:       String,
    pub current_root_index: usize,
    pub total_roots:        usize,
    pub files_scanned:      usize,
    pub threats_found:      usize,
    pub elapsed_secs:       u64,
}

pub struct ScanSummary {
    pub files_scanned: usize,
    pub threats_found: usize,
    pub cancelled:     bool,
}

// ── Internal helper: scan one file and log ─────────────────────────────

fn process_file(
    path:          &Path,
    db:            &Arc<SignatureDb>,
    yara:          &Arc<YaraEngine>,
    files_scanned: &mut usize,
    threats_found: &mut usize,
) {
    if path.metadata().map(|m| m.len() == 0).unwrap_or(false) { return; }
    *files_scanned += 1;
    log::debug!("  scanning: {}", path.display());

    match scan_file(path, db, yara) {
        Ok(result) => {
            let vs = match &result.verdict {
                Verdict::Clean         => "clean",
                Verdict::Suspicious(_) => "suspicious",
                Verdict::Malicious(_)  => "malicious",
            };
            let _ = db.log_scan(&result.path, &result.sha256, vs);
            match &result.verdict {
                Verdict::Malicious(name) => {
                    *threats_found += 1;
                    log::warn!("THREAT  [{}]  {}  →  {}",
                        &result.sha256[..8], name, result.path);
                    let _ = quarantine::quarantine_file(path, db, &result.sha256, name);
                }
                Verdict::Suspicious(r) => {
                    log::warn!("SUSPECT [{}]  {}  →  {}",
                        &result.sha256[..8], r, result.path);
                }
                Verdict::Clean => {}
            }
        }
        Err(e) => log::debug!("skip {:?}: {:?}", path, e),
    }
}

// ── Phase 1: walk directories ──────────────────────────────────────────

pub fn scan_paths(
    roots:    &[String],
    db:       Arc<SignatureDb>,
    yara:     Arc<YaraEngine>,
    progress: Arc<Mutex<ScanProgress>>,
    cancel:   Arc<AtomicBool>,
) -> ScanSummary {
    let started       = Instant::now();
    let total_roots   = roots.len();
    let mut files_scanned = 0usize;
    let mut threats_found = 0usize;

    {
        let mut p = progress.lock().unwrap();
        p.active = true; p.cancelled = false; p.phase = "dirs".into();
        p.files_scanned = 0; p.threats_found = 0;
        p.total_roots = total_roots; p.current_root_index = 0;
        p.current_file = String::new(); p.current_root = String::new();
    }

    if roots.is_empty() {
        log::warn!("scan_paths called with no roots");
    } else {
        log::info!("Scan started → {} location(s)", total_roots);
    }

    'outer: for (idx, root) in roots.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) { break 'outer; }

        log::info!("Scanning [{}/{}]: {}", idx + 1, total_roots, root);
        {
            let mut p = progress.lock().unwrap();
            p.current_root = root.clone();
            p.current_root_index = idx + 1;
        }

        let path = Path::new(root);

        if path.is_file() {
            // Single file (e.g., a process executable passed directly)
            if cancel.load(Ordering::Relaxed) { break 'outer; }
            process_file(path, &db, &yara, &mut files_scanned, &mut threats_found);
            if files_scanned % 5 == 0 {
                let mut p = progress.lock().unwrap();
                p.files_scanned = files_scanned;
                p.threats_found = threats_found;
                p.elapsed_secs  = started.elapsed().as_secs();
                p.current_file  = path.to_string_lossy().to_string();
            }
        } else {
            // Directory walk
            for entry in WalkDir::new(root)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                if cancel.load(Ordering::Relaxed) {
                    log::info!("Scan cancelled after {} files", files_scanned);
                    break 'outer;
                }

                let p = entry.path();
                process_file(p, &db, &yara, &mut files_scanned, &mut threats_found);

                if files_scanned % 5 == 0 {
                    let elapsed = started.elapsed().as_secs();
                    let mut prog = progress.lock().unwrap();
                    prog.files_scanned = files_scanned;
                    prog.threats_found = threats_found;
                    prog.elapsed_secs  = elapsed;
                    prog.current_file  = p.to_string_lossy().to_string();
                }
            }
        }
    }

    finish_progress(&progress, &cancel, files_scanned, threats_found, &started)
}

// ── Phase 2: scan running process executables ──────────────────────────

pub fn scan_running_processes(
    db:       Arc<SignatureDb>,
    yara:     Arc<YaraEngine>,
    progress: Arc<Mutex<ScanProgress>>,
    cancel:   Arc<AtomicBool>,
    started:  Instant,
) -> (usize, usize) {
    let exe_paths = crate::process_scan::get_running_executables();

    {
        let mut p = progress.lock().unwrap();
        p.phase        = "processes".into();
        p.current_root = format!("Running processes ({} executables)", exe_paths.len());
        p.current_root_index = 0;
        p.total_roots  = 0; // hides drive/folder tiles in UI
    }

    let mut files_scanned = 0usize;
    let mut threats_found = 0usize;

    for path_str in &exe_paths {
        if cancel.load(Ordering::Relaxed) { break; }
        let path = Path::new(path_str);
        process_file(path, &db, &yara, &mut files_scanned, &mut threats_found);

        if files_scanned % 10 == 0 {
            let mut p = progress.lock().unwrap();
            p.files_scanned += files_scanned;
            p.threats_found += threats_found;
            p.elapsed_secs   = started.elapsed().as_secs();
            p.current_file   = path_str.clone();
            files_scanned = 0; threats_found = 0; // avoid double-counting
        }
    }

    // Final update
    {
        let mut p = progress.lock().unwrap();
        p.files_scanned += files_scanned;
        p.threats_found += threats_found;
        p.elapsed_secs   = started.elapsed().as_secs();
    }

    (files_scanned, threats_found)
}

// ── Finish helper ─────────────────────────────────────────────────────

fn finish_progress(
    progress:      &Arc<Mutex<ScanProgress>>,
    cancel:        &Arc<AtomicBool>,
    files_scanned: usize,
    threats_found: usize,
    started:       &Instant,
) -> ScanSummary {
    let was_cancelled = cancel.load(Ordering::Relaxed);
    let elapsed       = started.elapsed();
    {
        let mut p = progress.lock().unwrap();
        p.active        = false;
        p.cancelled     = was_cancelled;
        p.files_scanned = files_scanned;
        p.threats_found = threats_found;
        p.elapsed_secs  = elapsed.as_secs();
        p.current_file  = String::new();
    }

    if was_cancelled {
        log::info!("Scan cancelled — {} files, {} threat(s) ({:.1}s)",
            files_scanned, threats_found, elapsed.as_secs_f32());
    } else if threats_found == 0 {
        log::info!("Scan complete — {} files, no threats ({:.1}s)",
            files_scanned, elapsed.as_secs_f32());
    } else {
        log::warn!("Scan complete — {} files, {} THREAT(S) quarantined ({:.1}s)",
            files_scanned, threats_found, elapsed.as_secs_f32());
    }

    ScanSummary { files_scanned, threats_found, cancelled: was_cancelled }
}
