# docs/ — vlt Documentation

[English](README.md) | [Español](es/README.md)

This directory contains user-facing documentation for the vlt secrets manager.

## Files

| File | Description |
|------|-------------|
| `ARCHITECTURE.md` | High-level system architecture, design philosophy, components, data flow, and security model. |
| `ARCHITECTURE-MERMAID.md` | Complete visual diagrams (Mermaid) covering Core, PKI mTLS, SSE Real-Time Sync, and SQLite Schema v7. |
| `USER_GUIDE.md` | Comprehensive user guide covering CLI, GUI, TUI, installation, and troubleshooting. |
| `SYNC-DEPLOYMENT.md` | Master guide for multi-device synchronization, Zero-Trust mTLS, Docker, and multi-vault operations. |
| `WINDOWS-CLIENT-GUIDE.md` | Complete setup, compilation, and sync guide for Windows users (CLI, TUI, Quick, Toast alerts). |
| `TLS-CERTIFICATES.md` | How to generate and manage mTLS PKI certificates for the sync server and clients. |
| `OTP-TOTP-GUIDE.md` | Complete guide for 2FA, TOTP/HOTP generation, and security advantages. |
| `MOBILE-ROADMAP.md` | Architecture roadmap for upcoming iOS and Android mobile clients. |
| `ROADMAP.md` | Project vision, version history, planned features, and security issue tracker. |
| `SYNC_API.md` | API reference for the `vlt-sync` server (endpoints, authentication, SSE events). |
| `quick-access.md` | Setup guide for the floating search popup (`vlt-gui --quick`). |

## Quick Access

The Quick Access popup (`vlt-gui --quick`) is a floating search window for rapid secret lookup and clipboard copy. It's the fastest way to access secrets — designed to be bound to a global hotkey (e.g., `Shift+Cmd+K`).

### Keybindings

| Key | Action |
|-----|--------|
| Type | Search secrets (live filter) |
| ↑ / ↓ | Navigate results |
| Enter | Copy selected secret |
| Esc | Close popup |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Secret copied successfully |
| 1 | Cancelled (Esc pressed) |
| 2 | Error |

### Quick Setup (macOS)

**Recommended — macOS Shortcuts:**
1. Open **Shortcuts** app → Create new shortcut
2. Add action: **Run Shell Script** → `/path/to/vlt-gui --quick`
3. Info tab → Check **Use as Quick Action**
4. **System Settings → Keyboard → Keyboard Shortcuts → Services** → assign `Shift+Cmd+K`

**Alternative — Raycast:**
1. Extensions → Create Script Command
2. Name: `vlt-quick`, script: `#!/bin/bash /path/to/vlt-gui --quick`
3. Assign `Shift+Cmd+K` in Raycast settings

### How It Works

1. `vlt-gui --quick` checks for a running GUI instance via local IPC socket or opens directly
2. If vault is locked, prompts for master password inside the popup
3. Search bar with live filtering by secret name
4. Press Enter → copies value to clipboard with auto-clear security
5. Window auto-closes after copying

### Requirements

- `vlt-gui` on PATH (or in `/Applications/vlt.app` / same directory as `vlt`)
- macOS: `pbcopy` (built-in)
- Linux: `xclip` or `wl-clipboard`