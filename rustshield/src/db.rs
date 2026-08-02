use rusqlite::{Connection, Result, params};
use std::sync::Mutex;
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct QuarantineItem {
    pub id:              i64,
    pub sha256:          String,
    pub threat_name:     String,
    pub original_path:   String,
    pub quarantine_path: String,
    pub quarantined_at:  String,
}

#[derive(Serialize, Clone)]
pub struct ExceptionItem {
    pub id:        i64,
    pub sha256:    Option<String>,
    pub file_path: Option<String>,
    pub file_name: String,
    pub reason:    Option<String>,
    pub added_at:  String,
}

pub struct SignatureDb {
    conn: Mutex<Connection>,
}

impl SignatureDb {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS signatures (
                sha256 TEXT PRIMARY KEY, threat_name TEXT NOT NULL, severity INTEGER NOT NULL DEFAULT 5
            );
            CREATE TABLE IF NOT EXISTS scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL, sha256 TEXT NOT NULL, verdict TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_scan_verdict ON scan_log (verdict, id DESC);

            CREATE TABLE IF NOT EXISTS quarantine_log (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256           TEXT NOT NULL,
                threat_name      TEXT NOT NULL,
                original_path    TEXT NOT NULL,
                quarantine_path  TEXT NOT NULL,
                quarantined_at   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                restored         INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS exceptions (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256    TEXT,
                file_path TEXT,
                file_name TEXT NOT NULL,
                reason    TEXT,
                added_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            );
        ")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    // ── Signatures ─────────────────────────────────────────────────────
    pub fn add_signature(&self, sha256: &str, name: &str, sev: i32) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute("INSERT OR REPLACE INTO signatures (sha256,threat_name,severity) VALUES(?1,?2,?3)",
                  params![sha256,name,sev])?;
        Ok(())
    }
    pub fn lookup(&self, sha256: &str) -> Result<Option<(String,i32)>> {
        let c = self.conn.lock().unwrap();
        let mut s = c.prepare("SELECT threat_name,severity FROM signatures WHERE sha256=?1")?;
        let mut r = s.query(params![sha256])?;
        if let Some(row) = r.next()? { Ok(Some((row.get(0)?,row.get(1)?))) } else { Ok(None) }
    }

    // ── Scan log ───────────────────────────────────────────────────────
    pub fn log_scan(&self, file_path: &str, sha256: &str, verdict: &str) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute("INSERT INTO scan_log (file_path,sha256,verdict) VALUES(?1,?2,?3)",
                  params![file_path,sha256,verdict])?;
        Ok(())
    }
    pub fn max_log_id(&self) -> Result<i64> {
        let c = self.conn.lock().unwrap();
        Ok(c.query_row("SELECT COALESCE(MAX(id),0) FROM scan_log",[],|r| r.get(0))?)
    }
    pub fn detections_since(&self, since_id: i64) -> Result<Vec<(String,String,String,String)>> {
        let c = self.conn.lock().unwrap();
        let mut s = c.prepare("SELECT file_path,sha256,verdict,timestamp FROM scan_log WHERE id>?1 AND verdict!='clean' ORDER BY id ASC")?;
        s.query_map(params![since_id],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).and_then(|r| r.collect())
    }
    pub fn get_detections(&self, page: i64, per_page: i64) -> Result<Vec<(String,String,String,String)>> {
        let c = self.conn.lock().unwrap();
        let mut s = c.prepare("SELECT file_path,sha256,verdict,timestamp FROM scan_log WHERE verdict!='clean' ORDER BY id DESC LIMIT ?1 OFFSET ?2")?;
        s.query_map(params![per_page,page*per_page],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).and_then(|r| r.collect())
    }
    pub fn count_detections(&self) -> Result<i64> {
        let c = self.conn.lock().unwrap();
        Ok(c.query_row("SELECT COUNT(*) FROM scan_log WHERE verdict!='clean'",[],|r| r.get(0))?)
    }
    pub fn recent_detections(&self, limit: i64) -> Result<Vec<(String,String,String,String)>> {
        self.get_detections(0,limit)
    }

    // ── Quarantine ─────────────────────────────────────────────────────
    pub fn log_quarantine(&self, sha256: &str, threat_name: &str, original_path: &str, quarantine_path: &str) -> Result<i64> {
        let c = self.conn.lock().unwrap();
        c.execute("INSERT INTO quarantine_log (sha256,threat_name,original_path,quarantine_path) VALUES(?1,?2,?3,?4)",
                  params![sha256,threat_name,original_path,quarantine_path])?;
        Ok(c.last_insert_rowid())
    }
    pub fn get_quarantine_items(&self) -> Result<Vec<QuarantineItem>> {
        let c = self.conn.lock().unwrap();
        let mut s = c.prepare("SELECT id,sha256,threat_name,original_path,quarantine_path,quarantined_at FROM quarantine_log WHERE restored=0 ORDER BY id DESC")?;
        s.query_map([],|r| Ok(QuarantineItem {
            id:r.get(0)?,sha256:r.get(1)?,threat_name:r.get(2)?,
            original_path:r.get(3)?,quarantine_path:r.get(4)?,quarantined_at:r.get(5)?,
        })).and_then(|r| r.collect())
    }
    pub fn get_quarantine_item(&self, id: i64) -> Result<Option<QuarantineItem>> {
        let c = self.conn.lock().unwrap();
        let mut s = c.prepare("SELECT id,sha256,threat_name,original_path,quarantine_path,quarantined_at FROM quarantine_log WHERE id=?1")?;
        let mut r = s.query(params![id])?;
        if let Some(row) = r.next()? {
            Ok(Some(QuarantineItem {
                id:row.get(0)?,sha256:row.get(1)?,threat_name:row.get(2)?,
                original_path:row.get(3)?,quarantine_path:row.get(4)?,quarantined_at:row.get(5)?,
            }))
        } else { Ok(None) }
    }
    pub fn mark_restored(&self, id: i64) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute("UPDATE quarantine_log SET restored=1 WHERE id=?1", params![id])?;
        Ok(())
    }

    // ── Exceptions ─────────────────────────────────────────────────────
    pub fn add_exception(&self, sha256: Option<&str>, file_path: Option<&str>, file_name: &str, reason: Option<&str>) -> Result<i64> {
        let c = self.conn.lock().unwrap();
        c.execute("INSERT INTO exceptions (sha256,file_path,file_name,reason) VALUES(?1,?2,?3,?4)",
                  params![sha256,file_path,file_name,reason])?;
        Ok(c.last_insert_rowid())
    }
    pub fn get_exceptions(&self) -> Result<Vec<ExceptionItem>> {
        let c = self.conn.lock().unwrap();
        let mut s = c.prepare("SELECT id,sha256,file_path,file_name,reason,added_at FROM exceptions ORDER BY id DESC")?;
        s.query_map([],|r| Ok(ExceptionItem {
            id:r.get(0)?,sha256:r.get(1)?,file_path:r.get(2)?,
            file_name:r.get(3)?,reason:r.get(4)?,added_at:r.get(5)?,
        })).and_then(|r| r.collect())
    }
    pub fn remove_exception(&self, id: i64) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute("DELETE FROM exceptions WHERE id=?1", params![id])?;
        Ok(())
    }
    pub fn is_path_excepted(&self, path: &str) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        let n: i64 = c.query_row(
            "SELECT COUNT(*) FROM exceptions WHERE file_path IS NOT NULL AND file_path=?1",
            params![path], |r| r.get(0))?;
        Ok(n > 0)
    }
    pub fn is_hash_excepted(&self, sha256: &str) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        let n: i64 = c.query_row(
            "SELECT COUNT(*) FROM exceptions WHERE sha256 IS NOT NULL AND sha256=?1",
            params![sha256], |r| r.get(0))?;
        Ok(n > 0)
    }
}
