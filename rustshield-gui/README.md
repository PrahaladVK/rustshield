# RustShield GUI — Tauri v2 + React

This is the desktop frontend for the RustShield engine. It communicates
with the engine over HTTP on `127.0.0.1:7878`.

## Prerequisites

- **Node.js LTS** → https://nodejs.org  (v20+ recommended)
- **Rust + MSVC build tools** → already set up from the engine project
- **WebView2** → ships with Windows 11; Windows 10 users install from
  https://developer.microsoft.com/microsoft-edge/webview2/

## Running in dev mode (quickest way to see it)

Open **two terminals side by side** in VS Code:

**Terminal 1 — start the engine first:**
```
cd rustshield
cargo run
```
Wait until you see `API listening on http://127.0.0.1:7878`.

**Terminal 2 — start the GUI:**
```
cd rustshield-gui
npm install        ← only needed the first time
npm run tauri dev
```

A window opens in a few seconds. The sidebar shows "Engine running" in
green when the connection is healthy.

## Building a distributable installer

```
cd rustshield-gui
npm run tauri build
```

Output is in `src-tauri/target/release/bundle/`. On Windows you get an
NSIS installer (.exe) and an MSI — both work as a one-click install.

## Project structure

```
rustshield-gui/
├── src/                   React frontend
│   ├── App.tsx            Full dashboard (Dashboard / Scan / Detections)
│   └── main.tsx           Entry point
├── src-tauri/             Tauri (Rust) shell
│   ├── src/
│   │   ├── lib.rs         Boots the Tauri window
│   │   └── main.rs        Binary entry point (hides console in release)
│   ├── tauri.conf.json    Window config + CSP (allows calls to :7878)
│   └── capabilities/      Tauri v2 permission model
├── index.html
├── vite.config.ts
└── package.json
```

## What the dashboard shows

- **Dashboard tab** — Protection status banner, stat cards, last 5 detections
- **Scan tab** — Directory picker, Start scan button, per-run result summary
- **Detections tab** — Full detection history table (polls engine every 10 s)
