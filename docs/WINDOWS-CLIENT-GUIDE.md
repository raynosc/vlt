# Windows Client and Synchronization Guide

[English](WINDOWS-CLIENT-GUIDE.md) | [Español](es/WINDOWS-CLIENT-GUIDE.md)

This guide details how to compile, configure, and operate the **`vlt` client on Windows (10/11)**, enabling secure vault synchronization with macOS and Linux devices using mutual TLS (mTLS) and native Windows Toast notifications.

---

## 1. Available Windows Binaries

The project uses pure-Go embedded SQLite (`modernc.org/sqlite`) without CGo dependencies, producing high-performance standalone `.exe` binaries.

| Binary | Windows Purpose |
| :--- | :--- |
| **`vlt.exe`** | CLI for vault management (`add`, `get`, `edit`, `list`, `otp`, `audit`, `sync`). |
| **`vlt-gui.exe`** | Native desktop GUI (Fyne) with Watchtower, 3-column layout, single-instance IPC, and auto-lock. |
| **`vlt-tui.exe`** | Interactive Terminal UI in Windows Terminal / PowerShell with multi-vault switching (`Tab`). |
| **`vlt-quick.exe`** | Floating popup for instantaneous search and clipboard copy with auto-clearing. |
| **`vlt-sync.exe`** | Synchronization server (if hosted on Windows). |

### Cross-Compilation from macOS / Linux
Run from project root:
```bash
make build-windows
```
Binaries will be output to `bin/*.exe` (`vlt-gui.exe` compiled via MinGW-w64).

---

## 2. Issue Client mTLS Certificates (on Admin Machine)

On the admin machine hosting the Root CA (`ca.pem` and `ca-key.pem`), issue a client certificate:

```bash
./bin/vlt pki client \
  --ca ./certs/ca.pem \
  --ca-key ./certs/ca-key.pem \
  --name "windows-pc" \
  --out ./certs
```

This outputs:
* `windows-pc.pem` (Client public certificate)
* `windows-pc-key.pem` (Client private key)

---

## 3. Transfer Files to the Windows Machine

Securely transfer:
1. Binaries: `vlt.exe`, `vlt-tui.exe`, `vlt-quick.exe`.
2. Certificates:
   * `ca.pem` (Root CA)
   * `windows-pc.pem` (Client Cert)
   * `windows-pc-key.pem` (Client Key)
3. Initial Database:
   * The `.sqlite` vault file (e.g. `vault.sqlite`).

---

## 4. Setup on Windows (PowerShell)

### Step 1: Create Directories
```powershell
# Create standard XDG config directories
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.config\passwd"
New-Item -ItemType Directory -Force -Path "C:\Tools\vlt\certs"

# Copy database to standard path
Copy-Item ".\vault.sqlite" "$env:USERPROFILE\.config\passwd\vault.sqlite"

# Copy certificates
Copy-Item ".\ca.pem", ".\windows-pc.pem", ".\windows-pc-key.pem" "C:\Tools\vlt\certs\"

# Move binaries to C:\Tools\vlt and add to PATH
Move-Item ".\vlt.exe", ".\vlt-tui.exe", ".\vlt-quick.exe" "C:\Tools\vlt\"
$env:Path += ";C:\Tools\vlt"
```

### Step 2: Initialize mTLS Sync
```powershell
.\vlt.exe sync init `
  --server "https://192.168.0.104:8443" `
  --tls-ca "C:\Tools\vlt\certs\ca.pem" `
  --tls-cert "C:\Tools\vlt\certs\windows-pc.pem" `
  --tls-key "C:\Tools\vlt\certs\windows-pc-key.pem"
```

### Step 3: Test Initial Pull
```powershell
.\vlt.exe sync pull
```

---

## 5. Daily Operations on Windows

### A. Real-Time Sync Listener & Toast Alerts
```powershell
.\vlt.exe sync listen
```
When changes occur remotely, `vlt` automatically updates and triggers a native Windows Toast notification.

### B. Interactive Terminal UI
```powershell
.\vlt-tui.exe
```
* **Vault Switching**: Press `Tab` or `← / →` on unlock to switch between vaults.
* **Live TOTP**: Instant code view and copy.

### C. Quick Search Popup
```powershell
.\vlt-quick.exe
```
* Live search and press `Enter` to copy.
* Auto-clears the clipboard safely after 30 seconds.
