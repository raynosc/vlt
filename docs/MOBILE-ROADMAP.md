# Roadmap and Architecture Plan: Mobile Application (iOS / Android)

[English](MOBILE-ROADMAP.md) | [Español](es/MOBILE-ROADMAP.md)

This document establishes the technical plan, security considerations, and the task list (TODO) for extending the `vlt` ecosystem to mobile devices.

---

## 1. Critical Mobile Security Considerations

| Area | Risk / Requirement | Architectural Solution |
| :--- | :--- | :--- |
| **Cryptography** | Desynchronization risk if encryption is rewritten. | **Shared Go Core**: Compile `internal/crypto`, `internal/store` and `internal/sync` via `gomobile` / C-FFI into a unified binary (`.xcframework` / `.aar`). |
| **Biometrics (FaceID / TouchID)** | Avoid asking for the master key on each use without compromising security. | **Secure Enclave / Android Keystore**: After the first unlock, derive a secondary key wrapped in hardware with `kSecAccessControlBiometryAny` flags. |
| **Memory at Rest** | Password leakage when the app goes into the background. | **Background Zeroize**: Clear data structures in memory and lock the vault immediately upon entering the background. |
| **Screenshots** | Password theft via screenshots or screen recording. | **FLAG_SECURE (Android)** and **Window hiding in `sceneWillResignActive` (iOS)** with blurred screen/placeholder. |
| **Clipboard** | Passwords remaining indefinitely in the clipboard. | **Auto-clear timer**: Automatically clear the clipboard 30 or 45 seconds after a secret is copied. |

---

## 2. TODO and Phase Plan

### Phase 1: Onboarding and QR Pairing
- [ ] **1.1** Implement CLI command `vlt sync export-qr` to generate a pairing QR with the sync payload.
- [ ] **1.2** Add "Link Mobile Device" button in `vlt-gui` that displays the QR code on screen.
- [ ] **1.3** Define the QR payload schema (Server URL, `vault_uuid`, `api_key`, `sync_encryption_key`).

### Phase 2: Bridge Package in Go
- [ ] **2.1** Create the `pkg/bridge` package with C-compatible interface / `gomobile` for:
  - `UnlockVault(password string) -> sessionHandle`
  - `SearchSecrets(query string) -> JSON`
  - `GetSecret(id string) -> JSON`
  - `SaveSecret(secretJSON string) -> error`
  - `SyncVault() -> error`
- [ ] **2.2** Automate `.xcframework` (iOS) and `.aar` (Android) compilation in the `Makefile`.

### Phase 3: Mobile App Interface
- [ ] **3.1** Design mobile UI (Secrets list, Quick search, Password detail, OTP Generator).
- [ ] **3.2** Integrate QR code scanning with the device camera for imports and 2FA/TOTP.
- [ ] **3.3** Implement biometric flow with automatic idle timeout locking (1 min, 5 min, immediate).

### Phase 4: Autofill Provider Extension
- [ ] **4.1** Implement `CredentialProviderExtension` on iOS for Safari and native apps.
- [ ] **4.2** Implement `AutofillService` on Android.
- [ ] **4.3** Ensure the Autofill extension queries the local database in <50ms using blind HMAC indexes.

### Phase 5: Background Synchronization
- [ ] **5.1** Automatic synchronization of changes when opening the app or unlocking with biometrics.
- [ ] **5.2** Support for silent background fetch.
