# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Active development |
| < 0.1.0 | ❌ Not supported |

## Scope

RustShield is a Windows endpoint security engine. The following areas are
in scope for security reports:

- **Engine (Rust)**: vulnerabilities in the detection pipeline, API, quarantine
  manager, or file watcher that could allow malware to bypass detection or
  cause the engine to behave in an unsafe way
- **GUI (Tauri/React)**: vulnerabilities in the desktop application such as
  XSS in the WebView, privilege escalation, or unsafe handling of quarantine data
- **API**: issues with the local REST API (127.0.0.1:7878) such as
  unintended external exposure or lack of input validation
- **YARA rules**: false negatives that allow known malware families to pass
  undetected, or false positives that quarantine legitimate system files

The following are **out of scope**:
- Issues requiring physical access to the machine
- Social engineering attacks
- Bugs in third-party dependencies (report those upstream — yara-x, axum, etc.)
- The engine not having a kernel driver or Microsoft AV certification
  (this is an intentional scope limitation for a capstone project)

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by emailing the project maintainer directly:

> **Email:** vkprahalad004@gmail.com  
> **Subject line:** `[RustShield Security] Brief description`

Include in your report:
1. A description of the vulnerability
2. Steps to reproduce
3. The potential impact
4. Your suggested fix (optional but appreciated)

You will receive an acknowledgement within **48 hours** and a full response
within **7 days**. If the issue is confirmed, a patched version will be
released and you will be credited in the changelog (unless you prefer to
remain anonymous).

## Disclosure Policy

RustShield follows **coordinated disclosure**:
- Maintainer is notified privately
- A fix is developed and tested
- A new version is released with the fix
- The vulnerability is disclosed publicly in the release notes after the fix
  is available

## Important Notice

RustShield is a **final year academic capstone project** and is not intended
for production use in enterprise environments without further hardening. It
operates entirely in user mode without kernel driver support or Microsoft AV
certification. Use it at your own risk in production settings.
