# vlt — Secure Secrets Manager

[English](README.md) | [Español](docs/es/README.md)

A local-first, zero-knowledge secrets and password manager for everyone — from everyday users and teams to developers. Stores passwords, logins, 2FA/TOTP codes, API keys, TLS certificates, and SSH keys in an encrypted SQLite vault — with rich metadata extraction, Watchtower security audits, and a modern native GUI.

**Architecture**: encryption and decryption happen exclusively client-side. The vault file contains only ciphertext and HMAC blind indexes for secret values and metadata.

## Binaries

| Binary | Description |
|--------|-------------|
| `vlt` | CLI for all vault operations |
| `vlt-gui` | Native GUI (Fyne) with 3-column layout, Watchtower, and dark mode |
| `vlt-tui` | Terminal UI (Bubble Tea) for CLI lovers |
| `vlt-quick` | Floating search popup for rapid secret copy |
| `vlt-sync` | Sync server for cross-device vault sync (see [Deployment Guide](docs/SYNC-DEPLOYMENT.md)) |

## Quick Start

```bash
# Build all binaries for current platform
make build

# Build cross-platform (darwin arm64 + amd64)
make build-all

# Run all tests
make test

# Initialize a new vault (generates a 24-word recovery kit)
./bin/vlt init

# Store secrets (prompts securely for masked value in console — never in bash history)
./bin/vlt add github-token
./bin/vlt add api-key --type api_key

# Pipe secret from standard input
echo -n "my-api-key-value" | ./bin/vlt add ci-token --stdin

# Import certificates and SSH keys (auto-detects format and extracts metadata)
./bin/vlt add --file cert.pem
./bin/vlt add --file ~/.ssh/id_ed25519
./bin/vlt add --file bundle.p12

# Import from other password managers (Bitwarden, Apple Passwords, Chrome, KeePass, CSV, JSON)
./bin/vlt import passwords.csv

# List and search
./bin/vlt list
./bin/vlt list --kind certificate
./bin/vlt list --expiring 30
./bin/vlt search github

# Inspect certificates without storing
./bin/vlt inspect cert.pem
./bin/vlt inspect --json cert.pem

# Retrieve secrets
./bin/vlt get github-token

# Generate Zero-Trust mTLS certificates (CA, Server with SANs, Client)
./bin/vlt pki generate --out ./certs --hosts "192.168.0.104,localhost" --client "mac-laptop"

# Run the native GUI
./bin/vlt-gui

# Run the Quick Access popup
./bin/vlt-quick

# Run the terminal UI
./bin/vlt-tui
```

## Makefile Targets

```bash
# ── Local CI & Quality Gates (Pre-Commit / Pre-Push) ─────────────────────────
make check         # Run gofmt + go vet + golangci-lint + unit tests
make vuln          # Scan for vulnerabilities with govulncheck
make ci            # Run full CI suite: lint + vuln + tests with race detector

# ── Testing ──────────────────────────────────────────────────────────────────
make test          # Run all unit tests
make test-all      # Run with -race detector
make test-cover    # Coverage report → coverage.html

# ── Building ─────────────────────────────────────────────────────────────────
make build         # Build all binaries to bin/ for current platform
make build-all     # Cross-compile darwin/arm64 + darwin/amd64
make build-linux   # Cross-compile linux/amd64 + linux/arm64
make build-windows # Cross-compile Windows binaries (vlt.exe, vlt-gui.exe, etc.)
make clean         # Remove bin/ and coverage files

# ── Running ──────────────────────────────────────────────────────────────────
make run-gui       # go run ./cmd/vlt-gui
make run-tui       # go run ./cmd/vlt-tui
make run-quick     # go run ./cmd/vlt-gui --quick
make run-cli       # vlt CLI
make help          # Show all targets
```

## Security

| Feature | Implementation |
|---------|---------------|
| Key derivation | **Argon2id** (t=3, m=64MB, p=4) |
| Encryption | **AES-256-GCM** per-secret envelope |
| Metadata Security | Zero-knowledge encrypted metadata with HMAC blind indexing |
| Password verification | **Constant-time** HKDF-SHA256 |
| Vault format | SQLite — zero plaintext on disk |
| Zero-knowledge | Encryption/decryption only in client RAM |
| Recovery | 24-word BIP-39 mnemonic recovery kit |
| Memory safety | Sensitive byte buffers are zeroized upon use |

### Non-Interactive Automation

`PASSWD_MASTER_PASSWORD` allows non-interactive use (scripts, CI pipelines).
Use `--no-env` to disable environment variable reading in paranoid environments:

```bash
PASSWD_MASTER_PASSWORD=secret ./bin/vlt list
./bin/vlt --no-env list                      # ignores env, prompts for password
```

## Vault Location

```
macOS:   ~/.config/passwd/vault.sqlite (or ~/Library/Application Support/passwd/)
Linux:   ~/.config/passwd/vault.sqlite
Windows: %APPDATA%/passwd/vault.sqlite
```

Override with `--vault-path <path>` or use multi-vault switching with `vlt vault switch <name>`.

## Supported Formats

| Format | Extensions | Notes |
|--------|------------|-------|
| CSV Export | `.csv` | Auto-detects `,`, `;`, `\t` (Bitwarden, Apple, Chrome, KeePass, etc.) |
| JSON Export | `.json` | Standard JSON export format |
| X.509 Certificate | `.pem`, `.crt`, `.cer` | Full metadata extraction (CN, issuer, SANs, expiry) |
| SSH Private Key | `id_rsa`, `id_ed25519`, `id_ecdsa` | RSA, Ed25519, ECDSA support |
| SSH Public Key | `.pub` | Type + fingerprint display |
| PKCS#12 Bundle | `.p12`, `.pfx` | Password-protected bundles |
| TOTP / HOTP | OTPAuth URL in metadata | Live code generation with countdown |

## GUI Features (vlt-gui & vlt-gui.exe)

- **Modern 3-column layout**: sidebar (categories + vaults) | list | detail
- **Native Zero-Permission Global Hotkeys (macOS)**: System-wide shortcuts (`Shift+Cmd+Space` for Quick Access, `Shift+Cmd+V` for Vault GUI) powered by native Carbon `RegisterEventHotKey` (requires **zero** Accessibility or Input Monitoring permissions)
- **Dynamic Hotkey Re-registration**: Modify your shortcut combinations in Settings anytime with immediate, real-time in-memory updates
- **Crisp Retina Menu Bar / System Tray**: Minimalist monochrome template icon living in the macOS status bar for background persistence
- **Single-Instance IPC**: Opening the app when already running brings the existing window to front with zero startup delay
- **Inactivity Auto-Lock**: Configurable auto-lock timer in Settings (`5m`, `15m`, `30m`, `60m`, `Never`)
- **Watchtower** security dashboard: weak passwords, duplicate detection, missing 2FA, expiring certificates
- **Type-specific & Brand Icons**: Passwords, API keys, certificates, SSH keys, notes, plus high-contrast SVG badges for known services
- **Offline Disk Favicon Cache**: Fast local caching at `~/.config/passwd/cache/favicons/` for instantaneous scrolling
- **Inline editing** for all fields: username, URL, password with reveal/hide toggle, TOTP
- **Dark theme & Responsive Density**: Streamlined list view fitting 10-12 items on screen seamlessly

## macOS Native Installation & Packaging

You can package and install `vlt` as a native macOS Application (`vlt.app` with Apple Retina `.icns` and CLI integration):

```bash
# Package into build/vlt.app
make app

# Install into /Applications/vlt.app and CLI into PATH (/usr/local/bin/vlt)
make install-mac

# Clean uninstallation (preserves your encrypted ~/.config/passwd/ vaults)
make uninstall-mac
```

## Zero-Trust mTLS PKI & Synchronization

`vlt` includes a built-in PKI generator to issue mutual TLS (mTLS) certificates with ECDSA P-256:

```bash
# 1. Generate full PKI hierarchy (CA, Server with SANs, and Client):
./bin/vlt pki generate --out ./certs --hosts "192.168.0.104,localhost" --client "mac-laptop"

# 2. Issue additional client certificates (e.g. for a Windows PC):
./bin/vlt pki client --ca ./certs/ca.pem --ca-key ./certs/ca-key.pem --name "windows-pc" --out ./certs
```

**Files generated in `./certs/`**:
* `ca.pem` — Root Certificate Authority (shared with server and all clients).
* `ca-key.pem` — CA private key (keep secure/offline to issue future client certs).
* `server.pem` & `server-key.pem` — Server TLS certificate (with IP/DNS SANs) and private key.
* `client.pem` & `client-key.pem` — Client mTLS certificate and private key.

## Documentation

- [Spanish Documentation Index (Documentación en Español)](docs/es/README.md)
- [Architecture Diagrams (Mermaid)](docs/ARCHITECTURE-MERMAID.md) — Complete visual diagrams of Core, PKI mTLS, and Real-Time Sync.
- [System Architecture](docs/ARCHITECTURE.md) — High-level architecture, data flows, and security model.
- [Windows Client & Sync Guide](docs/WINDOWS-CLIENT-GUIDE.md) — Complete setup, compilation, and sync guide for Windows users.
- [TLS, PKI & mTLS Guide](docs/TLS-CERTIFICATES.md) — Complete guide on certificate generation, anatomy, SANs, and mTLS.
- [Sync Server Deployment Guide](docs/SYNC-DEPLOYMENT.md) — Docker, Compose, Kubernetes, and TLS operations.
- [2FA & TOTP User Guide](docs/OTP-TOTP-GUIDE.md) — What is TOTP, security advantages, and complete usage guide.
- [Quick Access Popup Guide](docs/quick-access.md) — Setup and keybindings for floating search popup.
- [Mobile App Roadmap](docs/MOBILE-ROADMAP.md) — Mobile architecture, Go mobile bridge, and biometrics.
- [AI Agent Guidelines](AGENTS.md) — Architecture map and security invariants for AI pair programmers.

## Requirements

- **Go 1.24+ / 1.26+**
- SQLite via `modernc.org/sqlite` (pure Go, zero CGo required for CLI/Sync/TUI)
- `golang.org/x/crypto` (Argon2, HKDF, SSH parsing)

## Install

```bash
go install github.com/raynosc/vlt/cmd/vlt@latest
go install github.com/raynosc/vlt/cmd/vlt-gui@latest
go install github.com/raynosc/vlt/cmd/vlt-tui@latest
go install github.com/raynosc/vlt/cmd/vlt-quick@latest
go install github.com/raynosc/vlt/cmd/vlt-sync@latest
```

Or build from source:

```bash
git clone https://github.com/raynosc/vlt.git
cd vlt
make build
```

## License

MIT