# Changelog

All notable changes to RustShield are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned
- Layer 4: ML inference using ONNX model trained on EMBER dataset (`ort` crate)
- Network monitor: active connection tracking via Windows IP Helper API
- Process monitor: suspicious parent→child spawn detection via ETW/WMI
- Windows Service wrapper for persistent background operation
- ACL hardening on quarantine folder (deny-execute via Win32 Security API)

---
## [0.1.1] — 2026-07-28

### Fixed
- GUI: added parentheses around `??` and `||` operator on App.tsx line 535
  to fix Babel parser error (Nullish coalescing mixed with logical operators)

## [0.1.0] — 2026-07-25

Initial release — core engine and desktop GUI functional end-to-end.

### Engine (Rust)

#### Detection Pipeline
- **Layer 0**: Exception whitelist — path and SHA-256 hash check (zero I/O, fastest path)
- **Layer 1**: SHA-256 signature matching against SQLite database seeded from public hash feeds
- **Layer 2**: YARA-X pattern scanning (VirusTotal's pure-Rust YARA rewrite, stable June 2025)
  - `eicar.yar` — EICAR standard test file detection
  - `ransomware.yar` — shadow copy deletion, ransom note keyword clusters
  - `suspicious_pe.yar` — process injection triad, anti-debug, LSASS access, PowerShell cradles
- **Layer 3**: PE structural heuristics — per-section Shannon entropy (threshold 7.4 bits/byte,
  >30% of non-resource sections), W^X section detection, known packer section names (UPX0/1/2, MPRESS…)
  - Multi-signal requirement (2+ indicators) reduces false positives on legitimate packed installers
  - Trusted path exclusion: System32, SysWOW64, Program Files skipped for heuristics

#### Real-time Protection
- File system watcher via `notify` crate (wraps `ReadDirectoryChangesW`)
- Monitors 7 locations resolved dynamically from `%USERPROFILE%` and `%TEMP%`:
  Downloads · Desktop · Documents · Temp · AppData Startup folder · Public Downloads · ProgramData
- Malicious files quarantined atomically within milliseconds of detection

#### Scanning
- **Quick scan**: user folders + Windows Temp + all currently running process executables
  (enumerated via `CreateToolhelp32Snapshot` / `QueryFullProcessImageNameW`)
- **Full scan**: all detected drive letters (A–Z enumerated at runtime)
- **Custom scan**: any user-specified directory path
- Live progress: files scanned, current file, current drive/location, elapsed time, threats found
- Cancellable at any point via `Arc<AtomicBool>` checked per file (zero lock overhead)
- Drive tiles show correct labels: drive letters for Full scan, folder abbreviations for Quick scan

#### Quarantine
- Atomic file move (same-volume `fs::rename`) to `C:\ProgramData\RustShield\Quarantine\`
- Original path + threat name recorded in `quarantine_log` table
- Restore: reverse move back to original path
- Post-restore exception option: add hash + path to whitelist

#### Data Layer
- SQLite with WAL journal mode (concurrent reads during watcher writes)
- Tables: `signatures`, `scan_log`, `quarantine_log`, `exceptions`
- Index on `(verdict, id DESC)` for paginated history queries
- Hash import tool: `cargo run --bin import_hashes -- hashes.csv`

#### API
- Local-only Axum REST API on `127.0.0.1:7878` (CORS-enabled for WebView)
- Routes: `/status`, `/scan`, `/scan/cancel`, `/scan/progress`, `/scan/report`,
  `/detections`, `/quarantine`, `/quarantine/restore`, `/exceptions`

### GUI (Tauri v2 + React + TypeScript)

- **Home**: protection status banner, RTP toggle with live watched-path list, last scan summary,
  threat stat cards, recent threat list
- **Scan**: Quick / Full / Custom preset selector, live progress with drive/location tile grid,
  process scan phase indicator, cancel button, post-scan report download (.txt)
- **History**: paginated detection log (50/page, intersection-observer infinite scroll),
  total detection count badge in sidebar
- **Quarantine**: list isolated files with restore modal (Yes/No exception prompt),
  manual exception button per file
- **Exceptions**: hash + path whitelist management, remove entries

### Tech Stack
- Rust 1.75+ · axum 0.7 · notify 6.1 · yara-x 0.x · rusqlite 0.31 (bundled)
- sha2 0.10 · walkdir 2 · tower-http 0.6 · tokio 1.x
- Tauri v2.x · React 18 · TypeScript · Vite 6
- Target: Windows 10 (build 1903+) / Windows 11 · x86_64-pc-windows-msvc

[Unreleased]: https://github.com/PrahaladVK/rustshield/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/PrahaladVK/rustshield/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/PrahaladVK/rustshield/releases/tag/v0.1.0
