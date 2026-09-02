---
name: vlt-architecture
description: Deep architecture guide for vlt (core crypto, SQLite schema v7, CLI/GUI/TUI layers, and memory management).
---

# vlt Architecture Skill

This skill explains how the internal layers of `vlt` interact and how to extend them without introducing regressions or security vulnerabilities.

---

## 1. Key Derivation & Cryptographic Flow

```
[ Master Password ] + [ Salt (Config Table) ] + [ Argon2id Params ]
                     │
                     ▼ (Argon2id: 64MB RAM, 3 iterations, 4 threads)
              [ Derived Key (32 bytes) ]
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
  [ Data Encryption ]     [ Blind Indexing ]
  AES-256-GCM + Nonce     HMAC-SHA256(Key, "passwd.name." + Name)
         │                       │
         ▼                       ▼
  `encrypted_value`       `name_lookup` (DB UNIQUE column)
  `encrypted_name`
  `encrypted_notes`
```

### Key Packaging (`internal/crypto/engine.go`)
* Ciphertext is packed into an envelope: `12-byte Nonce || Ciphertext || 16-byte Tag`.
* Helper functions: `crypto.PackEnvelope(nonce, ciphertext)` and `unpackEnvelope(blob)`.

---

## 2. SQLite Schema v7 Invariants (`internal/store`)

The secrets table layout in SQLite:
* `id TEXT PRIMARY KEY`: UUID v4.
* `name_lookup BLOB UNIQUE`: Blind HMAC index for constant-time exact match queries without decrypting all rows.
* `kind TEXT`: One of `password`, `api_key`, `certificate`, `ssh_key`, `note`, `other`.
* `encrypted_value BLOB`: Ciphertext of the secret payload.
* `encrypted_name BLOB`: Ciphertext of the secret name.
* `encrypted_notes BLOB`: Ciphertext of the notes.
* `encrypted_tags BLOB`: Ciphertext of the tags.
* `encrypted_metadata BLOB`: Ciphertext of structured metadata (JSON).
* `deleted_at DATETIME`: Soft-delete timestamp (Tombstone). If non-null, secret is treated as deleted and synced as a tombstone.

---

## 3. UI, Quick Access & Multi-Vault Selection

* **`internal/gui` (Fyne v2)**: Native desktop GUI. Uses 3-column layout (Sidebar, Secret List, Detail View). Pure business logic resides in `App` (`app.go`), UI rendering in `gui.go`.
  * **Unlock Selector**: Both `showUnlockScreen` and `showQuickUnlock` dynamically discover all `.sqlite` vaults via `config.ListVaults()` and provide interactive dropdowns to pick the vault before entering the master password.
  * **Brand Visual Engine (`internal/gui/brands.go`)**: Deterministic 2-pass brand detection using `brandPriorityOrder` (sub-services like AWS/Gmail evaluated before parent domains) and embedded crisp vector SVGs (`brand_svgs.go`).
  * **Native Zero-Permission Global Hotkeys (`internal/gui/hotkeys_darwin.go`)**: Uses native Carbon `RegisterEventHotKey` API via CGo. Listens for `Shift+Cmd+Space` (Quick Access) and `Shift+Cmd+V` (Main Vault GUI) globally system-wide without requiring any macOS Accessibility or Input Monitoring permissions.
  * **Dynamic Hotkey Re-Registration**: Modifying shortcuts in Settings hot-reloads active listeners in memory in real time without application restarts.
  * **Crisp Retina Systray / Menu Bar**: Minimalist monochrome template icon embedded in `app_icon.go` (`TrayIconResource`) that keeps the app resident in background when windows are closed.
* **`internal/tui` (Bubble Tea)**: Terminal UI with keyboard navigation (`j/k`, `/` search, `y` copy, `tab` view). In the unlock state, pressing `Tab` or `← / →` cycles across available vaults before entering credentials.
* **`internal/quick` & Raycast Integration**:
  * Lightweight popup with daemon socket support.
  * Raycast Script Commands in `scripts/macos/` (`vlt-quick-raycast.sh`) for instant global hotkey access (`Shift+Cmd+K`).

---

## 4. PKI & Zero-Trust mTLS Subsystem (`internal/crypto/pki.go`, `internal/cli/pki.go`)

* `GenerateFullPKISet`: Pure Go ECDSA P-256 generator that outputs Root CA (`ca.pem`), Server TLS cert with IP/DNS SANs (`server.pem`), and Client mTLS cert (`client.pem`).
* `GenerateClientCert`: Issues new client certificates on demand for additional devices.
* Apple & RFC 5280 compliant: leaf cert validity <= 365 days, `KeyUsage = x509.KeyUsageDigitalSignature`.
* Used by `vlt-sync --tls-client-ca` to enforce Zero-Trust mutual certificate verification.

---

## 5. Cross-Platform Compilation (`make build-windows`)

* CLI, Sync Server, TUI, and Quick Popup compile natively to Windows without CGo (`GOOS=windows GOARCH=amd64`).
* Desktop GUI compiles to Windows with MinGW-w64 (`x86_64-w64-mingw32-gcc -H=windowsgui`).
* Output artifacts: `bin/vlt.exe`, `bin/vlt-gui.exe`, `bin/vlt-sync.exe`, `bin/vlt-tui.exe`, `bin/vlt-quick.exe`.
* Native Windows Toast notifications implemented via PowerShell runtime in `internal/notify/notify.go`.
* Single-instance IPC on Windows uses fast loopback (`127.0.0.1:41882`), macOS/Linux uses Unix sockets (`~/.config/passwd/vlt-gui.sock`).

---

## 6. CI Quality Gates & Local Verification (`make check`, `make vuln`, `make ci`)

All agents and contributors must ensure 100% parity with GitHub Actions before pushing:
* **`make check`**: Runs `gofmt` + `go vet` + `golangci-lint` + unit tests. Must pass with **0 issues**.
* **`make vuln`**: Scans dependencies and Go runtime for CVEs via `govulncheck`.
* **`make ci`**: Runs `make lint` + `make vuln` + `go test -v -race ./...` (race detector).
* **`make build` & `make build-windows`**: Rebuilds all binaries in `bin/` and `bin/*.exe`.
