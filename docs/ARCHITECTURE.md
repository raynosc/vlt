# Architecture of vlt — Secure Secrets Manager

[English](ARCHITECTURE.md) | [Español](es/ARCHITECTURE.md)

`vlt` is a local-first, zero-knowledge secrets and password manager designed for everyone (everyday users, teams, and developers). It securely stores passwords, logins, 2FA/TOTP seeds, API keys, TLS certificates, and SSH keys in an encrypted SQLite vault, offering rich metadata extraction, Watchtower audits, native system tray persistence, and a modern native GUI.

## Design Philosophy

1. **Local-First & Offline Resilience:** The vault is a local SQLite database (`vault.sqlite`). All critical cryptographic operations (encryption, decryption, blind search) occur purely locally. Synchronization is an optional add-on.
2. **Zero-Knowledge:** Neither the sync server nor any external actor has access to encryption keys or plaintext secrets. Encryption and decryption occur exclusively client-side. The vault file and remote blobs contain only ciphertext.
3. **Security by Design:** Robust cryptographic practices from the ground up, including Argon2id key derivation, AES-256-GCM authenticated encryption, constant-time verification, and secure subprocess clipboard clearing via stdin pipes.
4. **Modularity & Discrete Components:** Functionality is organized into dedicated binaries (CLI, GUI, TUI, Quick Access, Sync Server) that can operate independently or together.
5. **Extensibility:** Support for multiple secret kinds (X.509, SSH, PKCS#12, TOTP) with an extensible JSON metadata envelope.
6. **Developer Experience (DX):** Streamlined CLI, rich shell workflows, and standard configuration paths.

## System Components

`vlt` is composed of several specialized binaries:

### 1. `vlt` (Command Line Interface - CLI)
The core secrets manager providing all fundamental vault operations:
* **Initialization:** `vlt init` generates a 24-word BIP-39 recovery kit.
* **Secret Management:** `add`, `get`, `edit`, `rm`, `list`, `search`, `import`, `export`.
* **PKI mTLS:** `vlt pki generate` and `vlt pki client` for zero-trust certificate infrastructure.
* **Inspection & Audit:** `inspect` previews certificates without storing; `audit` checks vault health via Watchtower.
* **Synchronization:** `sync` coordinates with `vlt-sync`.

### 2. `vlt-gui` (Native Graphical User Interface)
A native desktop GUI built with Fyne v2:
* **3-Column Layout:** Sidebar (categories, vaults), secret list, detail inspector.
* **Native Zero-Permission Global Hotkeys (macOS):** System-wide shortcut listeners (`Shift+Cmd+Space` and `Shift+Cmd+V`) powered by Carbon `RegisterEventHotKey` requiring zero system accessibility permissions.
* **Menu Bar / System Tray:** Crisp Retina monochrome icon keeping the process resident in the background when windows are closed.
* **Watchtower Security Dashboard:** Identifies weak, duplicate, pwned passwords and expiring certificates.
* **Inline Editing & OTP:** Live TOTP generation with countdowns and brand SVG icons.

### 3. `vlt-tui` (Terminal User Interface)
An interactive terminal interface built with Charm Bubble Tea for keyboard-driven navigation.

### 4. `vlt-quick` (Floating Quick Access Popup)
A lightweight search popup designed for rapid secret copy without opening the main window.

### 5. `vlt-sync` (Zero-Knowledge Sync Server)
A self-hosted synchronization server:
* **Blind State:** The server only sees encrypted blobs (`AES-256-GCM + AAD`), sequence numbers, and vault UUIDs.
* **Real-time SSE:** Event broadcasting over Server-Sent Events for instant multi-device updates.
* **Mutual TLS (mTLS):** Enforces cryptographic client identity via built-in PKI.

## Data Flow & Security Model

### Vault & Storage Format (Schema v7)
* All secrets are stored in a local SQLite file (`vault.sqlite`).
* Default paths:
  * macOS: `~/.config/passwd/vault.sqlite`
  * Linux: `~/.config/passwd/vault.sqlite`
  * Windows: `%APPDATA%/passwd/vault.sqlite`
* **Zero Plaintext on Disk:** Secret names are stored in `encrypted_name`, and exact queries use a blind HMAC index (`name_lookup = HMAC-SHA256(MasterKey, "passwd.name." + Name)`).

### Encryption Envelope
Each secret is encrypted independently:
1. **Master Key Derivation:** Argon2id (t=3, m=64MB, p=4) derives a 32-byte master key from the master password.
2. **Payload Encryption:** AES-256-GCM encrypts the secret value with a unique 12-byte nonce.
3. **Envelope Storage:** Stored as `Nonce (12B) || Ciphertext || Tag (16B)`.

### Clipboard Security (S-06 Invariant)
* Secrets are piped to detached child processes (`vlt __clear-clipboard`) exclusively through **`stdin`** (never command-line arguments / `argv`) to prevent exposure in process tables (`ps aux`).
* The clipboard auto-clears conditionally after 30 seconds if the content has not changed.
* All memory buffers containing plaintext are zeroized with `crypto.Zeroize`.

## Project Structure

* **`cmd/`:** Entry points for all binaries (`vlt`, `vlt-gui`, `vlt-tui`, `vlt-quick`, `vlt-sync`).
* **`internal/`:** Internal packages (`crypto`, `store`, `secret`, `gui`, `tui`, `sync`, `syncserver`, `notify`, `parse`, `otp`, `watchtower`).
* **`docs/`:** English documentation and `docs/es/` for Spanish documentation.
* **`scripts/`:** Packaging, installation (`scripts/macos/`), and verification scripts.
* **`build/`:** Native application bundle assets and `.icns` generators.
