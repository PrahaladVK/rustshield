<div align="center">

# 🛡 RustShield

**Lightweight Windows Endpoint Security Engine**

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)](https://www.microsoft.com/windows)

*Final Year Capstone Project — B.Tech CSE 2026*  
*Department of Computer Engineering & Technology, MIT-WPU Pune*

</div>

---

## What is RustShield?

RustShield is a Windows antivirus/endpoint-protection engine built in Rust as an alternative to Windows Defender. It combines three independent detection layers, real-time file system monitoring, a quarantine system, and a native Tauri v2 desktop GUI — all without a kernel driver, scoped intentionally to user-mode operation for a final-year capstone.

## Detection Pipeline

```
File arrives
   │
   ▼  Layer 0 — Exception whitelist      (path / hash — fastest, no I/O)
   │
   ▼  Layer 1 — SHA-256 signature DB     (SQLite, seeded from MalwareBazaar)
   │
   ▼  Layer 2 — YARA-X pattern rules     (catches whole malware families)
   │
   ▼  Layer 3 — PE structural heuristics (per-section entropy + W^X + packers)
   │
Verdict: Clean / Suspicious / Malicious
```

> **Planned — Layer 4**: ML inference via ONNX model trained on the EMBER dataset (`ort` crate)

## Features

| Feature | Status |
|---------|--------|
| SHA-256 signature scanning | ✅ Done |
| YARA-X pattern rules | ✅ Done |
| PE heuristics (entropy + W^X) | ✅ Done |
| Real-time file monitoring (7 locations) | ✅ Done |
| Quick scan (folders + running processes) | ✅ Done |
| Full scan (all drives, cancellable) | ✅ Done |
| Quarantine + restore | ✅ Done |
| Exception whitelist (hash + path) | ✅ Done |
| Scan report download (.txt) | ✅ Done |
| Tauri v2 desktop GUI | ✅ Done |
| ML inference layer (ONNX/EMBER) | 🔄 Planned |
| Network connection monitor | 🔄 Planned |
| Process spawn monitor | 🔄 Planned |
| Windows Service wrapper | 🔄 Planned |

## Quick Start

### Prerequisites

- **Rust** (1.75+): `https://rustup.rs`
- **Microsoft C++ Build Tools** (MSVC linker): `https://visualstudio.microsoft.com/visual-cpp-build-tools/`
- **Node.js LTS** (v20+): `https://nodejs.org`
- **WebView2**: ships with Windows 11; installer available for Windows 10

### Run the engine

```powershell
cd rustshield
cargo run
# API starts at http://127.0.0.1:7878
```

### Run the GUI

```powershell
cd rustshield-gui
npm install
npm run tauri dev
```

### Seed the signature database

Download a hash CSV from [MalwareBazaar](https://bazaar.abuse.ch/export/) (format: `sha256,threat_name`):

```powershell
cd rustshield
cargo run --bin import_hashes -- hashes.csv
```

### Test detection safely

Create a file containing the EICAR test string (a harmless industry-standard AV test):

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Drop it into `C:\Users\Public\Downloads` — RustShield detects and quarantines it within a second.

## Project Structure

```
rustshield/                 ← Rust engine
├── src/
│   ├── main.rs             Entry point
│   ├── api.rs              Axum REST API (7878)
│   ├── scanner.rs          3-layer detection pipeline
│   ├── full_scan.rs        Directory + process scanning
│   ├── watcher.rs          Real-time file monitor
│   ├── quarantine.rs       Isolate + restore files
│   ├── process_scan.rs     Running process enumeration (Win32)
│   ├── yara_scanner.rs     YARA-X engine wrapper
│   └── db.rs               SQLite (signatures, log, quarantine, exceptions)
├── rules/                  YARA rule files
│   ├── eicar.yar
│   ├── ransomware.yar
│   └── suspicious_pe.yar
└── Cargo.toml

rustshield-gui/             ← Tauri v2 + React GUI
├── src/
│   ├── App.tsx             Main dashboard (Home/Scan/History/Quarantine/Exceptions)
│   └── main.tsx
└── src-tauri/              Rust shell
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Engine | Rust 1.75+ · tokio · axum · walkdir |
| Detection | sha2 · yara-x · rusqlite (bundled) |
| File watch | notify (ReadDirectoryChangesW) |
| Process scan | windows-rs (ToolHelp32 + Threading) |
| GUI shell | Tauri v2 |
| GUI frontend | React 18 + TypeScript + Vite 6 |
| Data | SQLite (WAL mode) |

## Versioning

This project uses [Semantic Versioning](https://semver.org/):

- **0.x.y** — pre-release / capstone development
- **1.0.0** — production-ready with ML layer + network monitor

See [CHANGELOG.md](CHANGELOG.md) for full version history.

## License

MIT — see [LICENSE](LICENSE)
