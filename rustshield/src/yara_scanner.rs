// yara_scanner.rs
// YARA-X pattern scanning — the most important detection upgrade over
// pure hash matching. YARA rules describe malware *families* (byte
// patterns, string combinations, PE header traits) so a slightly
// modified variant of a known trojan still gets caught even if its
// hash doesn't match anything in the DB.
//
// YARA-X is VirusTotal's pure-Rust rewrite of YARA (stable June 2025).
// Unlike the original C library it has zero non-Rust dependencies, so
// it compiles everywhere without extra system packages.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraEngine {
    // Rules is compiled and read-only, but yara_x::Rules may not
    // publicly implement Sync (scanner creation borrows &Rules). Wrapping
    // in Mutex is the safe choice and doesn't hurt throughput — SQLite is
    // already serialized the same way.
    rules: Mutex<Rules>,
}

impl YaraEngine {
    /// Compile all .yar / .yara files found in `rules_dir`.
    /// Returns an Arc so it can be shared across the watcher thread,
    /// the Axum runtime, and spawn_blocking closures.
    pub fn load_from_dir(rules_dir: &str) -> anyhow::Result<Arc<Self>> {
        let mut compiler = Compiler::new();
        let dir = Path::new(rules_dir);
        let mut loaded = 0usize;

        if dir.exists() && dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let path = entry?.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yar" || ext == "yara" {
                    match fs::read_to_string(&path) {
                        Ok(src) => {
                            if let Err(e) = compiler.add_source(src.as_str()) {
                                log::warn!("YARA compile error in {:?}: {}", path, e);
                            } else {
                                loaded += 1;
                                log::debug!("Loaded YARA rule file: {:?}", path);
                            }
                        }
                        Err(e) => log::warn!("Could not read {:?}: {}", path, e),
                    }
                }
            }
        } else {
            log::warn!(
                "YARA rules directory '{}' not found — create it and add .yar files.",
                rules_dir
            );
        }

        log::info!("YARA engine ready: {} rule file(s) loaded", loaded);
        let rules = compiler.build();
        Ok(Arc::new(Self {
            rules: Mutex::new(rules),
        }))
    }

    /// Scan raw bytes. Returns the identifiers of every matching rule.
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        let rules = self.rules.lock().unwrap();
        let mut scanner = Scanner::new(&*rules);
        match scanner.scan(data) {
            Ok(results) => results
                .matching_rules()
                .map(|r| r.identifier().to_string())
                .collect(),
            Err(e) => {
                log::debug!("YARA scan error: {}", e);
                vec![]
            }
        }
    }

    /// Convenience: read the file then scan it.
    pub fn scan_file(&self, path: &Path) -> Vec<String> {
        match fs::read(path) {
            Ok(data) => self.scan_bytes(&data),
            Err(_) => vec![],
        }
    }
}
