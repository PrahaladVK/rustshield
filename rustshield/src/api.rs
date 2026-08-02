use axum::{extract::{Path,Query,State},routing::{delete,get,post},Json,Router};
use serde::{Deserialize,Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tower_http::cors::{Any,CorsLayer};

use crate::db::{ExceptionItem,QuarantineItem,SignatureDb};
use crate::full_scan::{scan_paths, scan_running_processes, ScanProgress};
use crate::quarantine::restore_file;
use crate::watcher::resolve_watch_paths;
use crate::yara_scanner::YaraEngine;
use crate::full_scan::detect_drives;

pub type SharedProgress = Arc<std::sync::Mutex<ScanProgress>>;
pub type SharedReport   = Arc<std::sync::Mutex<Option<ScanReport>>>;
pub type SharedCancel   = Arc<AtomicBool>;

#[derive(Clone)]
pub struct AppState {
    pub db:          Arc<SignatureDb>,
    pub yara:        Arc<YaraEngine>,
    pub progress:    SharedProgress,
    pub last_report: SharedReport,
    pub cancel:      SharedCancel,
}

static STARTED: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
pub fn init_uptime() { STARTED.get_or_init(Instant::now); }

// ── Report ─────────────────────────────────────────────────────────────
#[derive(Clone,Serialize,Default)]
pub struct ReportDetection { pub file_path:String, pub sha256:String, pub verdict:String, pub timestamp:String }
#[derive(Clone,Serialize,Default)]
pub struct ScanReport {
    pub engine_version:String, pub scan_path:String,
    pub files_scanned:usize,   pub threats_found:usize,
    pub duration_secs:f64,     pub cancelled:bool,
    pub detections:Vec<ReportDetection>,
}

// ── Response types ─────────────────────────────────────────────────────
#[derive(Serialize)]
struct StatusResponse { status:String, engine_version:&'static str, uptime_secs:u64, watch_paths:Vec<String>, drives:Vec<String> }

#[derive(Deserialize)] struct ScanRequest { path:String }
#[derive(Serialize)]   struct ScanResponse { files_scanned:usize, threats_found:usize, cancelled:bool }
#[derive(Serialize)]   struct Detection { file_path:String, sha256:String, verdict:String, timestamp:String }

#[derive(Deserialize)]
struct DetectionQuery { #[serde(default)] page:i64, #[serde(default="dpp")] per_page:i64 }
fn dpp()->i64{50}

#[derive(Serialize)] struct DetectionsResponse { items:Vec<Detection>, total:i64, page:i64, per_page:i64 }
#[derive(Deserialize)] struct RestoreRequest { id:i64, add_exception:bool }
#[derive(Serialize)]   struct RestoreResponse { success:bool, message:String, original_path:String }
#[derive(Deserialize)] struct AddExceptionRequest { sha256:Option<String>, file_path:Option<String>, file_name:String, reason:Option<String> }
#[derive(Serialize)]   struct SimpleOk { success:bool }

// ── Handlers ───────────────────────────────────────────────────────────

async fn status_handler(State(s):State<AppState>) -> Json<StatusResponse> {
    let uptime = STARTED.get().map(|t|t.elapsed().as_secs()).unwrap_or(0);
    let _=s.db.clone();
    Json(StatusResponse {
        status:"running".into(), engine_version:env!("CARGO_PKG_VERSION"),
        uptime_secs:uptime, watch_paths:resolve_watch_paths(), drives:detect_drives(),
    })
}

async fn progress_handler(State(s):State<AppState>) -> Json<ScanProgress> {
    Json(s.progress.lock().unwrap().clone())
}

async fn scan_handler(State(s):State<AppState>, Json(req):Json<ScanRequest>) -> Json<ScanResponse> {
    {
        let p = s.progress.lock().unwrap();
        if p.active { return Json(ScanResponse { files_scanned:0, threats_found:0, cancelled:false }); }
    }
    s.cancel.store(false, Ordering::Relaxed);

    // ── Determine roots ──────────────────────────────────────────────
    let (roots, label, include_processes) = match req.path.as_str() {
        "__FULL__" => {
            let drives = detect_drives();
            log::info!("Full system scan → drives: {:?}", drives);
            (drives, "Full system scan".to_string(), false)
        }
        "__QUICK__" => {
            // Quick scan = watched user folders + running process executables
            let paths = resolve_watch_paths();
            // Also add Windows temp dir if not already in list
            let win_temp = std::env::var("WINDIR")
                .map(|w| format!("{}\\Temp", w))
                .unwrap_or_default();
            let mut all_paths = paths;
            if !win_temp.is_empty() && std::path::Path::new(&win_temp).exists() {
                all_paths.push(win_temp);
            }
            log::info!("Quick scan → {} locations + running processes", all_paths.len());
            (all_paths, "Quick scan (folders + running processes)".to_string(), true)
        }
        other => (vec![other.to_string()], other.to_string(), false),
    };

    let id_before = s.db.max_log_id().unwrap_or(0);
    let scan_start = Instant::now();

    // ── Phase 1: directory / file scan ──────────────────────────────
    let (db1, yara1, prog1, cancel1) = (s.db.clone(), s.yara.clone(), s.progress.clone(), s.cancel.clone());
    let roots_clone = roots.clone();
    let mut summary = tokio::task::spawn_blocking(move || {
        scan_paths(&roots_clone, db1, yara1, prog1, cancel1)
    }).await.unwrap();

    // ── Phase 2: running process scan (Quick scan only) ─────────────
    if include_processes && !s.cancel.load(Ordering::Relaxed) {
        let (db2, yara2, prog2, cancel2) = (s.db.clone(), s.yara.clone(), s.progress.clone(), s.cancel.clone());
        let started_copy = scan_start;
        let (proc_files, proc_threats) = tokio::task::spawn_blocking(move || {
            // Re-mark as active for the process phase
            {
                let mut p = prog2.lock().unwrap();
                p.active = true;
            }
            let result = scan_running_processes(db2, yara2, prog2.clone(), cancel2, started_copy);
            {
                let mut p = prog2.lock().unwrap();
                p.active = false;
            }
            result
        }).await.unwrap();

        summary.files_scanned += proc_files;
        summary.threats_found += proc_threats;
    }

    let duration = scan_start.elapsed().as_secs_f64();
    let dets = s.db.detections_since(id_before).unwrap_or_default();
    let report = ScanReport {
        engine_version: format!("RustShield v{}", env!("CARGO_PKG_VERSION")),
        scan_path: label,
        files_scanned: summary.files_scanned,
        threats_found: summary.threats_found,
        duration_secs: duration,
        cancelled: summary.cancelled,
        detections: dets.into_iter().map(|(fp,h,v,ts)| ReportDetection{file_path:fp,sha256:h,verdict:v,timestamp:ts}).collect(),
    };
    *s.last_report.lock().unwrap() = Some(report);

    Json(ScanResponse { files_scanned:summary.files_scanned, threats_found:summary.threats_found, cancelled:summary.cancelled })
}

async fn cancel_scan_handler(State(s):State<AppState>) -> Json<SimpleOk> {
    s.cancel.store(true, Ordering::Relaxed);
    log::info!("Scan cancel requested");
    Json(SimpleOk{success:true})
}

async fn report_handler(State(s):State<AppState>) -> Json<Option<ScanReport>> {
    Json(s.last_report.lock().unwrap().clone())
}

async fn detections_handler(State(s):State<AppState>, Query(q):Query<DetectionQuery>) -> Json<DetectionsResponse> {
    let pp=q.per_page.clamp(1,200);
    let items=s.db.get_detections(q.page,pp).unwrap_or_default().into_iter()
        .map(|(fp,h,v,ts)| Detection{file_path:fp,sha256:h,verdict:v,timestamp:ts}).collect();
    let total=s.db.count_detections().unwrap_or(0);
    Json(DetectionsResponse{items,total,page:q.page,per_page:pp})
}

async fn quarantine_list_handler(State(s):State<AppState>) -> Json<Vec<QuarantineItem>> {
    Json(s.db.get_quarantine_items().unwrap_or_default())
}

async fn restore_handler(State(s):State<AppState>, Json(req):Json<RestoreRequest>) -> Json<RestoreResponse> {
    let item=s.db.get_quarantine_item(req.id).unwrap_or(None);
    match restore_file(req.id,&s.db) {
        Ok(original_path) => {
            if req.add_exception {
                if let Some(ref it)=item {
                    let fname=std::path::Path::new(&it.original_path)
                        .file_name().map(|n|n.to_string_lossy().to_string())
                        .unwrap_or_else(||it.original_path.clone());
                    let _=s.db.add_exception(Some(&it.sha256),Some(&it.original_path),&fname,Some("User restored from quarantine"));
                }
            }
            Json(RestoreResponse{success:true,message:"File restored successfully".into(),original_path})
        }
        Err(e)=>Json(RestoreResponse{success:false,message:e.to_string(),original_path:String::new()})
    }
}

async fn exceptions_list_handler(State(s):State<AppState>) -> Json<Vec<ExceptionItem>> {
    Json(s.db.get_exceptions().unwrap_or_default())
}

async fn add_exception_handler(State(s):State<AppState>, Json(req):Json<AddExceptionRequest>) -> Json<SimpleOk> {
    let ok=s.db.add_exception(req.sha256.as_deref(),req.file_path.as_deref(),&req.file_name,req.reason.as_deref()).is_ok();
    Json(SimpleOk{success:ok})
}

async fn remove_exception_handler(State(s):State<AppState>, Path(id):Path<i64>) -> Json<SimpleOk> {
    let ok=s.db.remove_exception(id).is_ok();
    Json(SimpleOk{success:ok})
}

pub fn build_router(state:AppState) -> Router {
    let cors=CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    Router::new()
        .route("/status",             get(status_handler))
        .route("/scan",               post(scan_handler))
        .route("/scan/cancel",        post(cancel_scan_handler))
        .route("/scan/progress",      get(progress_handler))
        .route("/scan/report",        get(report_handler))
        .route("/detections",         get(detections_handler))
        .route("/quarantine",         get(quarantine_list_handler))
        .route("/quarantine/restore", post(restore_handler))
        .route("/exceptions",         get(exceptions_list_handler).post(add_exception_handler))
        .route("/exceptions/:id",     delete(remove_exception_handler))
        .layer(cors)
        .with_state(state)
}
