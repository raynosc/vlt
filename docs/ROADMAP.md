# vlt Roadmap

[English](ROADMAP.md) | [Español](es/ROADMAP.md)

This document describes the long-term vision, planned features, and pending work for the project. Security, user experience, and cross-platform portability are prioritized.

---

## Vision

`vlt` aims to be the preferred secrets manager for solo developers and small teams who value:

*   **Total control**: data stored locally, zero reliance on third-party cloud services.
*   **Real security**: zero-knowledge encryption, no "security theater".
*   **Speed**: ultra-fast access via CLI, TUI, and GUI.
*   **Portability**: works identically on macOS, Linux, and Windows.

---

## Versions and Features

### v1.0.0 — Core Vault (Completed ✅)

*   Key derivation with Argon2id.
*   Per-secret AES-256-GCM encryption.
*   Full CLI with all base commands.
*   Interactive TUI.
*   Import and export (CSV, JSON, Bitwarden, KeePass, etc.).
*   Certificate management (X.509, SSH, PKCS#12).

### v1.1.0 — GUI + Biometrics (Completed ✅)

*   Native `vlt-gui` using Fyne.
*   Touch ID / Face ID unlock (macOS).
*   Quick Access popup (`vlt-quick`).
*   Watchtower dashboard (weak passwords, duplicates, expired certificates).
*   Glassmorphism dark theme.
*   Multi-vault support.

### v1.2.0 — Sync Server (Completed ✅)

*   Self-hostable synchronization server (`vlt-sync`).
*   Zero-knowledge synchronization between devices.
*   API key authentication.
*   Docker + Caddy support (automatic TLS).
*   Testing scripts for synchronization.

### v1.3.0 — Security and Cryptographic Hardening (Completed ✅)

All identified vulnerabilities were audited and resolved:

#### Tier 1 — Critical
* ✅ **S-01**: `sync_encryption_key` and `api_key` encrypted with AES-256-GCM and master key.
* ✅ **S-02**: TOTP/HOTP seed encrypted inside the metadata envelope.
* ✅ **S-06**: Secure clipboard clearing without passing secrets in process arguments.

#### Tier 2 — High
* ✅ **S-03**: Encrypted names and metadata (`encrypted_name` + blind index HMAC `name_lookup`).
* ✅ **S-04**: Removal of insecure Keychain; explicit master password zeroized in RAM.
* ✅ **S-05**: Sync with LWW resolution and full tombstone support.
* ✅ **S-12**: GUI unlock optimized to a single Argon2id derivation.

#### Tier 3 & 4
* ✅ **S-07 & S-08**: Sync server with rate-limiting, payload size limits, and Zero-Trust mTLS (`tls.RequireAndVerifyClientCert`).
* ✅ **S-10**: SQLite in WAL mode, `secure_delete = FAST`, permissions `0600`.
* ✅ **S-11**: AES-GCM with Additional Authenticated Data (AAD) to prevent blob transposition.
* ✅ **S-13**: Immediate zeroization of RAM buffers with `crypto.Zeroize`.
* ✅ **S-14**: BIP-39 compliant recovery mnemonic (24 words).

### v1.4.0 — OTP Engine / Authenticator and Audit (Completed ✅)
* ✅ RFC 6238 (TOTP) + RFC 4226 (HOTP) implementation in `internal/otp/`.
* ✅ QR code decoding and automatic import.
* ✅ Real-time countdown display in GUI and TUI.
* ✅ CLI `vlt otp` commands and Watchtower support.

### v1.5.0 — Zero-Trust mTLS and Cross-platform (Completed ✅)
* ✅ Integrated PKI generator (`vlt pki generate`, `vlt pki client`) compliant with RFC 5280 and Apple standards.
* ✅ Native Windows support (`make build-windows`, Toast notifications).
* ✅ Resilient auto-fallback in multi-vault configurations.
* ✅ Real-time synchronization via SSE with auto-pull and desktop notifications.

### v1.5.0 — Analysis and Auditing (Planned 📋)

| Feature | Description | Reference |
|---------|-------------|------------|
| **Password Strength Analysis** | Deep password analysis with `zxcvbn` | `openspec/changes/extend-check-password-analysis/` |
| **Breach Detection** | Integration with haveibeenpwned APIs (k-anonymity) | Proposal |
| **Certificate Chain Validation** | Certificate chain validation | Proposal |
| **SSH Known Hosts Analysis** | Detection of compromised keys in known_hosts | Proposal |

### v1.6.0 — UX / Accessibility (Planned 📋)

| Issue | Description | Reference |
|-------|-------------|------------|
| U-01 | No progress indicator during unlock | `ISSUES.md` |
| U-02 | `vlt get` prints to stdout by default (invert to clipboard) | `ISSUES.md` |
| U-03 | Weak password warning after confirmation | `ISSUES.md` |
| U-04 | Watchtower missing contextual "Rotate" actions | `ISSUES.md` |
| U-05 | Recovery kit only shown once | `ISSUES.md` |
| U-06 | Generic "decryption failed" message | `ISSUES.md` |
| U-07 | GUI missing idle auto-lock | `ISSUES.md` |
| U-08 | README over-promises biometrics | `ISSUES.md` |

### v2.0.0 — Ecosystem and Mobile (Future 🔮)

*   **Mobile app**: Native app (React Native or Flutter) for iOS/Android with sync server.
*   **CLI Plugin System**: Extensibility for custom commands.
*   **Secret Sharing**: Secure secret sharing (e.g., "this secret expires in 24h").
*   **Audit Logs**: Immutable log of secret access (local).
*   **Team Vaults**: Multi-user model with shared key (without a centralized server).

---

## Infrastructure and Tooling

| Area | Status | Notes |
|------|--------|-------|
| CI/CD | ✅ | Tests, linting, cross-platform build |
| Docker image | ✅ | `Dockerfile` for `vlt-sync` |
| Documentation | 🚧 | In progress — `ARCHITECTURE.md`, `USER_GUIDE.md`, `CONTRIBUTING.md` |
| OpenSpec SDD | ✅ | Complete artifacts for significant changes |
| Test coverage | 🚧 | High coverage in `cli`, `store`, `crypto`; improve in `sync` and `gui` |
| Security | 🚧 | Audit completed; pending fixes (v1.3.0) |

---

## How to read this roadmap

*   **Completed (✅)**: Feature ready for production.
*   **In Progress (🚧)**: Active work in this area.
*   **Planned (📋)**: Designed and prioritized; implementation pending.
*   **Future (🔮)**: Exploratory ideas with no estimated date.

Issues in `ISSUES.md` are prioritized by their ID (S-01 first, then S-02, etc.). Features in `openspec/` have their own design artifacts with detailed tasks.
