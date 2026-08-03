<div align="center">

# 🛡 RustShield

**Lightweight Windows Endpoint Security Engine**

[![Version](https://img.shields.io/badge/version-0.1.1-blue)](rustshield/CHANGELOG.md)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](rustshield/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)](https://www.microsoft.com/windows)

*Final Year Capstone Project — B.Tech CSE 2026*
*Department of Computer Engineering & Technology, MIT-WPU Pune*

</div>

---

## What is RustShield?

RustShield is a Windows antivirus / endpoint-protection engine built in Rust as
an alternative to Windows Defender. It combines three independent detection
layers, real-time file system monitoring across seven system locations, running
process scanning, a quarantine system with restore, and a native Tauri v2
desktop GUI — all without a kernel driver.

## Repository Layout

```
rustshield/        Rust engine — detection pipeline, API, watcher, quarantine
rustshield-gui/    Desktop GUI — Tauri v2 + React + TypeScript
```

## Detection Pipeline

```
File arrives
   │
   ▼  Layer 0 — Exception whitelist   (path / hash — zero I/O, fastest path)
   │
   ▼  Layer 1 — SHA-256 signature DB  (SQLite, seeded from MalwareBazaar)
   │
   ▼  Layer 2 — YARA-X pattern rules  (catches whole malware families)
   │
   ▼  Layer 3 — PE structural heuristics  (per-section entropy + W^X + packers)
   │
Verdict: Clean / Suspicious / Malicious
```

> **Planned — Layer 4:** ML inference via ONNX model trained on the EMBER dataset

## Quick Start

**Prerequisites:** Rust 1.75+, MSVC Build Tools, Node.js LTS v20+, WebView2

```powershell
# Terminal 1 — start the engine
cd rustshield
cargo run

# Terminal 2 — start the GUI
cd rustshield-gui
npm install
npm run tauri dev
```

Full setup instructions → [`rustshield/README.md`](rustshield/README.md)

## Features

| Feature | Status |
|---------|--------|
| SHA-256 signature scanning | ✅ |
| YARA-X pattern rules | ✅ |
| PE heuristics (entropy + W^X) | ✅ |
| Real-time monitoring (7 locations) | ✅ |
| Quick scan (folders + running processes) | ✅ |
| Full scan (all drives, cancellable) | ✅ |
| Quarantine + restore | ✅ |
| Exception whitelist (hash + path) | ✅ |
| Scan report download (.txt) | ✅ |
| Tauri v2 desktop GUI | ✅ |
| ML inference layer (ONNX/EMBER) | 🔄 Planned |
| Network connection monitor | 🔄 Planned |
| Process spawn monitor | 🔄 Planned |
| Windows Service wrapper | 🔄 Planned |

## Versioning

See [`rustshield/CHANGELOG.md`](rustshield/CHANGELOG.md) for full version history.

## License

MIT — see [`rustshield/LICENSE`](rustshield/LICENSE)
