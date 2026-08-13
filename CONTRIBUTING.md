# Contributing to RustShield

Thank you for your interest in contributing! RustShield is a final year
capstone project but contributions — bug reports, YARA rules, documentation
improvements, and code fixes — are welcome.

---

## Table of Contents

- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Code Style](#code-style)
- [Commit Message Format](#commit-message-format)
- [Pull Request Process](#pull-request-process)
- [YARA Rule Contributions](#yara-rule-contributions)
- [Reporting Bugs](#reporting-bugs)

---

## Getting Started

### Prerequisites

- Rust 1.75+ (`https://rustup.rs`)
- Microsoft C++ Build Tools (MSVC linker)
- Node.js LTS v20+ and npm v10+
- WebView2 Runtime (Windows 11 includes it; Windows 10 installer at microsoft.com)

### Running locally

```powershell
# Terminal 1 — engine
cd rustshield
cargo run

# Terminal 2 — GUI
cd rustshield-gui
npm install
npm run tauri dev
```

### Running tests

```powershell
cd rustshield
cargo test
```

To test detection without using real malware, drop an EICAR test file into
`C:\Users\Public\Downloads` — it is a harmless industry-standard string that
every AV tool recognises as a test threat:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

---

## How to Contribute

### 1. Fork and branch

```powershell
git clone https://github.com/PrahaladVK/rustshield.git
cd rustshield
git checkout -b feat/your-feature-name
```

Use these branch name prefixes:

| Prefix | Use for |
|--------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation changes |
| `chore/` | Build, config, dependency updates |
| `yara/` | New or updated YARA rules |

### 2. Make your changes

- Keep changes focused — one feature or fix per pull request
- Add or update comments in Rust files where the logic is non-obvious
- If you add a new detection technique, add a brief explanation of the
  research or source it is based on

### 3. Test before submitting

```powershell
cargo build          # must compile with no errors
cargo clippy         # no new warnings
cargo fmt --check    # code must be formatted
```

---

## Code Style

### Rust (engine)

- Follow standard Rust idioms — `cargo fmt` and `cargo clippy` are enforced
- Use `log::info!` / `log::warn!` / `log::error!` — no `println!` in
  production code paths
- Wrap shared state in `Arc<Mutex<T>>` — document why a Mutex is needed
  vs an `AtomicBool`
- Error handling: use `?` propagation; avoid `.unwrap()` except in tests
  or seeding code with a comment explaining why it is safe

### TypeScript / React (GUI)

- No external styling libraries — keep using inline styles matching the
  existing design tokens in `App.tsx`
- All icons must be inline SVG paths — no external icon library imports
- No `localStorage` or `sessionStorage` — all state stays in React state

### YARA rules

- Every rule **must** include a `meta` block with `description` and `severity`
- Rules targeting PE files must include `uint16(0) == 0x5A4D` as a condition
- Include a `filesize` guard to avoid scanning very large files
- New rules go in the appropriate existing file or a clearly named new `.yar`
  file in `rustshield/rules/`

---

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

[optional body]
```

Types: `feat` `fix` `docs` `chore` `yara` `refactor` `test`

Examples:
```
feat: add Shannon entropy check to PE section analysis
fix: parentheses around ?? and || in App.tsx (Babel parser error)
yara: add rule for Cobalt Strike beacon strings
docs: update CHANGELOG with v0.1.1 entry
```

---

## Pull Request Process

1. Ensure `cargo build`, `cargo clippy`, and `cargo fmt --check` all pass
2. Update `rustshield/CHANGELOG.md` under `## [Unreleased]` with what you changed
3. Open a pull request against the `main` branch
4. Fill in the PR description — what changed, why, and how to test it
5. A maintainer will review within a few days

Pull requests that break the build, add `.unwrap()` without justification,
or include test/real malware samples will be closed immediately.

---

## YARA Rule Contributions

YARA rule contributions are especially welcome. Before submitting:

- Test the rule against the EICAR test file to confirm it does not
  produce false positives on obvious benign inputs
- Cite the source or research the rule is based on in the `meta` block
- Rules **must not** contain or reference actual malware samples

---

## Reporting Bugs

Open a [GitHub Issue](https://github.com/PrahaladVK/rustshield/issues/new/choose)
using the **Bug report** template. Include:

- RustShield version (`cargo run` output shows version at startup)
- Windows version
- Steps to reproduce
- Engine log output (`$env:RUST_LOG="debug"; cargo run`)

For **security vulnerabilities**, do not open a public issue —
see [SECURITY.md](.github/SECURITY.md) instead.

---

## Questions?

Open a [Discussion](https://github.com/PrahaladVK/rustshield/discussions)
or mention it in an issue. 

Thank you for contributing!
