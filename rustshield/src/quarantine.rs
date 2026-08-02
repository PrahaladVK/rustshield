// quarantine.rs — move threats to an isolated folder, log to DB, support restore

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::db::SignatureDb;

const QUARANTINE_DIR: &str = "C:\\ProgramData\\RustShield\\Quarantine";

/// Move a malicious file to quarantine and log to DB.
/// Uses sha256+timestamp as filename to avoid collisions.
pub fn quarantine_file(
    path:        &Path,
    db:          &Arc<SignatureDb>,
    sha256:      &str,
    threat_name: &str,
) -> io::Result<PathBuf> {
    fs::create_dir_all(QUARANTINE_DIR)?;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dest_name = format!("{}_{}.quarantined", &sha256[..16], ts);
    let dest = Path::new(QUARANTINE_DIR).join(&dest_name);

    let original_path = path.to_string_lossy().to_string();
    fs::rename(path, &dest)?;

    let _ = db.log_quarantine(sha256, threat_name, &original_path, &dest.to_string_lossy());
    log::info!("Quarantined '{}' → '{}'", original_path, dest.display());
    Ok(dest)
}

/// Restore a quarantined file to its original location.
/// Returns Err if the original path's parent directory no longer exists.
pub fn restore_file(
    quarantine_item_id: i64,
    db: &Arc<SignatureDb>,
) -> io::Result<String> {
    let item = db.get_quarantine_item(quarantine_item_id)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Quarantine entry not found"))?;

    let qpath = Path::new(&item.quarantine_path);
    if !qpath.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound,
            "Quarantined file is missing from disk"));
    }

    let orig = Path::new(&item.original_path);
    if let Some(parent) = orig.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::rename(qpath, orig)?;
    let _ = db.mark_restored(quarantine_item_id);
    log::info!("Restored '{}' → '{}'", item.quarantine_path, item.original_path);
    Ok(item.original_path)
}
