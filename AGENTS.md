# AGENTS.md — AI Agent Guidelines & Context for `vlt`

Welcome, Agent. This repository contains **`vlt`**, a production-grade, local-first, zero-knowledge secrets manager written in Go.
This file and the `.agents/` directory provide complete architectural context, security invariants, package maps, and development workflows so any AI agent (Claude, Cursor, Copilot, OpenCode, Pi, Antigravity) can understand and extend this project safely.

---

## 1. Project Overview & Philosophy

* **Language**: Go (1.24+ / 1.26)
* **Architecture**: Local-first, Zero-Knowledge.
  * All encryption/decryption happens **exclusively client-side**.
  * The local database (`SQLite`) and remote sync server (`vlt-sync`) store **only ciphertext, HMAC blind indexes, and encrypted blobs**.
  * The server is **blind**; it never knows secret names, notes, tags, or passwords.
* **Security Discipline**:
  * Passwords and cryptographic keys must be zeroized in RAM immediately after use (`crypto.Zeroize(...)`).
  * Explicit master password prompt everywhere (auto-unlock via Keychain was deliberately removed to enforce zero-leakage).

---

## 2. Binaries (`cmd/`)

| Binary | Source | Description |
| :--- | :--- | :--- |
| `vlt` | `cmd/vlt/` | Core CLI for all vault operations (`add`, `get`, `edit`, `list`, `import`, `export`, `sync`, `pki`, `otp`, `audit`). |
| `vlt-gui` | `cmd/vlt-gui/` | Desktop GUI built with Fyne v2 (3-column layout, dark mode, Watchtower, live sync). |
| `vlt-tui` | `cmd/vlt-tui/` | Terminal UI built with Charm Bubble Tea. |
| `vlt-quick` | `cmd/vlt-quick/` | Floating search popup for rapid secret copy. |
| `vlt-sync` | `cmd/vlt-sync/` | Zero-knowledge synchronization server with REST + SSE real-time events. |

---

## 3. Package Map (`internal/`)

```
internal/
├── crypto/        # Argon2id KDF, AES-256-GCM, HMAC-SHA256 blind indexing, BIP39 recovery kit, PKI mTLS generator, Zeroize()
├── store/         # SQLite schema v7, encrypted metadata storage, tombstone management, WAL mode
├── secret/        # Domain entities (Secret, Kind, Envelope format)
├── sync/          # Client sync engine (CAS sequence numbers, LWW conflict resolution, SSE listener)
├── syncserver/    # Server sync engine (HTTP REST endpoints, Broadcaster, SSE on /events, SQLite store)
├── notify/        # Cross-platform desktop notifications (macOS AppleScript, Linux notify-send)
├── parse/         # Universal CSV parser (auto-delimiter, fuzzy header aliases, BOM stripping)
├── otp/           # RFC 6238 TOTP/HOTP generator and QR code parser
├── watchtower/    # Security audit engine (weak, reused, duplicate, expired, pwned passwords)
├── gui/           # Fyne v2 desktop frontend
├── tui/           # Bubble Tea terminal frontend
├── quick/         # Compact search-as-you-type popup logic
├── daemon/        # Local background Unix domain socket daemon
├── keychain/      # OS keychain integration (optional/explicit only)
├── config/        # XDG configuration file paths (~/.config/passwd/)
└── version/       # Application versioning
```

---

## 4. Critical Security Invariants (MANDATORY)

When modifying or generating code in this repository:

1. **Zeroization of Sensitive Memory**:
   * Any `[]byte` containing plaintext passwords, derived keys, or API tokens must be cleared with `defer crypto.Zeroize(slice)` or `crypto.Zeroize(slice)`.
2. **Schema v7 Invariants (`name_lookup`)**:
   * In schema v7, secret names are stored encrypted in `encrypted_name`.
   * The database uses `name_lookup = HMAC-SHA256(masterKey, "passwd.name." + name)` as a blind index for fast unique lookups without revealing plaintext names.
   * Never store plaintext names in the database.
3. **Zero Knowledge in Sync**:
   * The sync server payload (`SyncPayload`) is encrypted client-side with `sync_encryption_key` using AES-256-GCM + AAD before transmission.
   * The server only sees `vault_uuid`, `seq`, `key_hash`, and `encrypted_blob`.
4. **No Plaintext Credential Leaks in CLI**:
   * Never encourage or require passing passwords via CLI flags (`--password "xxx"`). Prefer interactive masked prompts or `--stdin`.
5. **Clipboard Security (Auto-Clear & Stdin Pipe)**:
   * When copying secrets to the clipboard, spawn the auto-clear child process (`vlt __clear-clipboard`) passing the secret exclusively via `stdin` (pipe) to prevent exposure in process tables (`argv`/`ps aux`).
   * Never pass secrets as command-line arguments.

---

## 5. Security-Oriented TDD Protocol (Sec-TDD)

All new features, cryptographic primitives, parsers, and API endpoints must adhere to **Security-Oriented Test-Driven Development (Sec-TDD)**:

1. **Phase 1 — Threat Modeling & Red Test (Adversarial First)**:
   * Write failing tests before writing implementation code.
   * Write specific **Security Invariant Tests**:
     - *Memory Zeroization*: Test that plaintext buffers are zeroed out after operations.
     - *Timing-Attack Resistance*: Verify constant-time checks (`subtle.ConstantTimeCompare`).
     - *Boundary / Hard Lockout*: Test lockout limits and circuit breakers.
     - *Negative / Malformed Input*: Test invalid signatures, truncated buffers, manipulated nonces, corrupted tags.
   * Write **Fuzz Targets (`Fuzz*`)**: For any component ingesting external data (parsers, decoders, envelope unpackers).

2. **Phase 2 — Green Implementation (Secure by Default)**:
   * Write the minimum secure implementation that satisfies invariants.
   * Never take security shortcuts (no global secrets in RAM, no plaintext logs, no hardcoded salts).

3. **Phase 3 — Continuous Verification & Refactor**:
   * Run `make check` (Lint + Gosec AST + Unit Tests).
   * Run `make fuzz` (Mutation Fuzz Testing).
   * Run `make ci` (Full CI with Race Detector + Vulnerability Scanner).

---

## 6. Development, Testing & CI Quality Conventions

```bash
# 1. Mandatory Local Pre-Commit & Pre-Push Quality Gate (gofmt + go vet + golangci-lint + gosec + unit tests)
make check

# 2. Dependency Vulnerability Scan (govulncheck)
make vuln

# 3. Security AST Scanner (gosec)
make sec

# 4. Mutation Fuzz Testing Suite
make fuzz

# 5. Full Local CI Suite (lint + sec + vuln + tests with race detector)
make ci

# 6. Build all local platform binaries into bin/
make build

# 7. Package macOS Native Bundle (build/vlt.app with Retina .icns)
make app

# 8. Install/Uninstall macOS Bundle and CLI
make install-mac
make uninstall-mac

# 9. Build cross-platform (darwin arm64/amd64, linux amd64/arm64, windows)
make build-all

# 10. Generate mTLS PKI certificates
./bin/vlt pki generate --out ./certs --hosts "192.168.0.104,localhost" --client "mac-laptop"

# 11. Run Docker sync server locally
docker compose up -d
```

> [!IMPORTANT]
> **Post-Edit & Pre-Push Invariant (MANDATORY)**:
> Whenever Go source code is modified:
> 1. Always run `make check` in local terminal before committing to ensure **0 lint issues** and **100% test pass** matching GitHub Actions CI.
> 2. Always run `make build` (and `make build-windows` when modifying UI/cross-platform packages) to keep binaries in `bin/` fresh.

---

## 6. Skills & Extended Guides (`.agents/skills/`)

For specialized workflows, check the skills in `.agents/skills/`:
* [vlt-architecture](file:///.agents/skills/vlt-architecture/SKILL.md) — Deep architectural guide, crypto flow, SQLite schema migrations, and CI quality gates.
* [vlt-sync-ops](file:///.agents/skills/vlt-sync-ops/SKILL.md) — Deploying, configuring, and testing `vlt-sync` (Docker, Compose, K8s, TLS, SSE).
* [vlt-security-auditing](file:///.agents/skills/vlt-security-auditing/SKILL.md) — Security rules, memory auditing, and Watchtower checks.
