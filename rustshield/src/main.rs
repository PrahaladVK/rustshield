mod api;
mod db;
mod full_scan;
mod process_scan;
mod quarantine;
mod scanner;
mod watcher;
mod yara_scanner;

use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::thread;

use api::{AppState, init_uptime};
use db::SignatureDb;
use full_scan::ScanProgress;
use yara_scanner::YaraEngine;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    init_uptime();
    log::info!("RustShield v{} starting...", env!("CARGO_PKG_VERSION"));

    let db = Arc::new(SignatureDb::open("rustshield_signatures.db").expect("failed to open DB"));
    seed_test_signatures(&db);
    log::info!("Signature database ready");

    let yara       = YaraEngine::load_from_dir("rules").expect("failed to load YARA rules");
    let progress   = Arc::new(Mutex::new(ScanProgress::default()));
    let last_report= Arc::new(Mutex::new(None));
    let cancel     = Arc::new(AtomicBool::new(false));

    let watcher_db   = db.clone();
    let watcher_yara = yara.clone();
    thread::spawn(move || {
        let paths = watcher::resolve_watch_paths();
        if paths.is_empty() {
            log::warn!("No watchable paths found — real-time protection inactive");
        } else {
            log::info!("Real-time protection covering {} location(s)", paths.len());
            if let Err(e) = watcher::watch_paths(&paths, watcher_db, watcher_yara) {
                log::error!("Watcher failed: {:?}", e);
            }
        }
    });

    let state = AppState { db, yara, progress, last_report, cancel };
    let app   = api::build_router(state);
    let addr  = "127.0.0.1:7878";
    let listener = tokio::net::TcpListener::bind(addr).await.expect("port 7878 already in use");
    log::info!("API ready on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

fn seed_test_signatures(db: &SignatureDb) {
    let eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    let _ = db.add_signature(eicar, "EICAR-Test-File", 1);
}
