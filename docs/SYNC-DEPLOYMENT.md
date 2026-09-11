# vlt-sync — Master Guide for Deployment, mTLS and Multi-Device Synchronization End-to-End

[English](SYNC-DEPLOYMENT.md) | [Español](es/SYNC-DEPLOYMENT.md)

This guide details the complete workflow to deploy and use `vlt`'s **Zero-Knowledge + Zero-Trust mTLS** synchronization across multiple clients (macOS, Windows, Linux) and a central server (`vlt-sync`).

---

## 📑 Table of Contents

1. [Architecture and Security Principles](#1-architecture-and-security-principles)
2. [Step 1: PKI Infrastructure Generation (mTLS Certificates)](#step-1-pki-infrastructure-generation-mtls-certificates)
3. [Step 2: Deploying the `vlt-sync` Server in Docker / VM](#step-2-deploying-the-vlt-sync-server-in-docker--vm)
4. [Step 3: Configuring and Registering the Primary Client (Mac)](#step-3-configuring-and-registering-the-primary-client-mac)
5. [Step 4: Connecting a Second Device (Windows PC / Linux VM)](#step-4-connecting-a-second-device-windows-pc--linux-vm)
6. [Step 5: Real-Time Synchronization and Desktop Notifications](#step-5-real-time-synchronization-and-desktop-notifications)
7. [Step 6: Multi-Vault Management (`vault` and `work`)](#step-6-multi-vault-management-vault-and-work)
8. [Step 7: Troubleshooting Guide](#step-7-troubleshooting-guide)

---

## 1. Architecture and Security Principles

```
┌─────────────────────────────────────────────────────────────┐
│                 CLIENT DEVICES (Mac / Windows)              │
│                                                             │
│  1. Local encryption with master key (AES-256-GCM + AAD)    │
│  2. Local SQLite database: ~/.config/passwd/*.sqlite        │
│  3. Network payload encryption with `sync_encryption_key`   │
│  4. Mutual authentication with client certificate (mTLS)    │
└─────────────┬───────────────────────────────────────────────┘
              │
              │ HTTPS (TLS 1.3 / mTLS / HTTP/2)
              ▼
┌─────────────────────────────────────────────────────────────┐
│                 vlt-sync SERVER (VM / Docker)               │
│                                                             │
│  • TCP Port: 8443                                           │
│  • Blind Server: Only stores encrypted blobs and sequences  │
│  • Real-time emitter: Server-Sent Events (SSE)              │
│  • Server database: /data/sync.db                           │
└─────────────────────────────────────────────────────────────┘
```

* **Zero-Knowledge**: The server never knows passwords, secret names, or notes. All encryption/decryption happens in the client's RAM.
* **Zero-Trust mTLS**: The server rejects in the handshake any connection that does not present a client certificate signed by the CA (`ClientAuth = tls.RequireAndVerifyClientCert`).
* **Atomic Concurrency (CAS / LWW)**: Monotonic version control (`seq`). If two devices save simultaneously, the conflict is resolved with effective timestamps (*Last-Write-Wins*) and tombstones for deletions.

---

## Step 1: PKI Infrastructure Generation (mTLS Certificates)

The entire certificate infrastructure is generated with the native `vlt pki` command on your primary machine (Mac). It strictly complies with RFC 5280 and Apple's requirements (ECDSA P-256 curves, validity <= 398 days, SANs by IP/DNS):

```bash
# 1. Generate CA, Server Certificate (with IP and domains), and Mac Client Certificate:
./bin/vlt pki generate --out ./certs --hosts "192.168.0.104,localhost" --client "mac-laptop"

# 2. Generate Client Certificate for your Windows PC:
./bin/vlt pki client --ca ./certs/ca.pem --ca-key ./certs/ca-key.pem --name "windows-pc" --out ./certs
```

### 📂 Files generated in `./certs/`:
| File | Role | Where to install |
| :--- | :--- | :--- |
| `ca.pem` | Root Certificate Authority Certificate | On the Server and **all** Clients |
| `ca-key.pem` | CA private key | Keep secure/offline (to sign future clients) |
| `server.pem` | Server TLS Certificate (with SANs) | On the Server |
| `server-key.pem` | Server private key | On the Server |
| `client.pem` | Mac mTLS Certificate | On your Mac |
| `client-key.pem` | Mac private key | On your Mac |
| `windows-pc.pem` | Windows PC mTLS Certificate | On your Windows PC |
| `windows-pc-key.pem`| Windows PC private key | On your Windows PC |

---

## Step 2: Deploying the `vlt-sync` Server in Docker / VM

### 1. Copy certificates to the server:
From your local machine, transfer the required files to the VM:
```bash
scp certs/ca.pem certs/server.pem certs/server-key.pem user@192.168.0.104:/opt/vlt-sync/certs/
```

### 2. Start the service with Docker Compose:
On the VM, in the `/opt/vlt-sync/` folder:

```yaml
# docker-compose.yml
services:
  vlt-sync:
    build: .
    image: vlt-sync:latest
    container_name: vlt-sync
    restart: unless-stopped
    ports:
      - "8443:8443"
    environment:
      - VLT_SYNC_ADDR=:8443
      - VLT_SYNC_DB_PATH=/data/sync.db
      - VLT_SYNC_TLS_CERT=/certs/server.pem
      - VLT_SYNC_TLS_KEY=/certs/server-key.pem
      - VLT_SYNC_TLS_CLIENT_CA=/certs/ca.pem
    volumes:
      - ./data:/data
      - ./certs:/certs:ro
    healthcheck:
      test: ["CMD-SHELL", "curl -k -f https://localhost:8443/healthz || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
```

```bash
docker compose up -d
```

### 3. Verify server status:
```bash
curl --cacert ./certs/ca.pem https://192.168.0.104:8443/healthz
# Expected response: {"status":"ok"}
```

---

## Step 3: Configuring and Registering the Primary Client (Mac)

### 1. Export mTLS environment variables (in `~/.zshrc` or terminal):
```bash
export VLT_SYNC_CA_CERT="./certs/ca.pem"
export VLT_SYNC_CLIENT_CERT="./certs/client.pem"
export VLT_SYNC_CLIENT_KEY="./certs/client-key.pem"
```

### 2. Register the vault with the server:
```bash
# Registers the 'vault' vault generating UUID, api_key, and sync_encryption_key:
./bin/vlt sync init --vault vault --server https://192.168.0.104:8443
```
*Expected output:*
```text
✅ Sync configured for vault: 2c450998-95db-4a5b-a5a1-47cdeb77b000
   Server: https://192.168.0.104:8443
   ✅ Registered with sync server
```

### 3. Push initial data:
```bash
./bin/vlt sync push --vault vault
# Expected output: ✅ Pushed to server (seq 1)
```

---

## Step 4: Connecting a Second Device (Windows PC / Linux VM)

To connect a second client to the same shared vault:

### 1. Transfer required files to the second client:
1. **mTLS Certificates**: `ca.pem`, `windows-pc.pem`, and `windows-pc-key.pem`.
2. **SQLite Database**: Transfer the full database including WAL files if they exist:
   ```bash
   scp ~/.config/passwd/vault.sqlite* user@192.168.0.104:~/.config/passwd/
   ```
   *(On Windows the destination path is `%APPDATA%\passwd\`)*.

### 2. Configure on the second client:

* **On Windows (PowerShell)**:
  ```powershell
  $env:VLT_SYNC_CA_CERT = "C:\Users\your_user\.config\passwd\certs\ca.pem"
  $env:VLT_SYNC_CLIENT_CERT = "C:\Users\your_user\.config\passwd\certs\windows-pc.pem"
  $env:VLT_SYNC_CLIENT_KEY = "C:\Users\your_user\.config\passwd\certs\windows-pc-key.pem"

  # Query existing secrets
  .\bin\vlt.exe list

  # Add or modify a secret
  .\bin\vlt.exe add production-server --type password

  # Send changes to the server
  .\bin\vlt.exe sync push
  ```

* **On Linux (Bash / Zsh)**:
  ```bash
  export VLT_SYNC_CA_CERT="/opt/vlt-sync/certs/ca.pem"
  export VLT_SYNC_CLIENT_CERT="/opt/vlt-sync/certs/client.pem"
  export VLT_SYNC_CLIENT_KEY="/opt/vlt-sync/certs/client-key.pem"

  vlt list
  vlt sync push
  ```

---

## Step 5: Real-Time Synchronization and Desktop Notifications

### A. In the Graphical Interface (`vlt-gui`) 🖥️
When opening `./bin/vlt-gui`:
* The Server-Sent Events (SSE) listener connects automatically in the background.
* Whenever another client pushes a change (`sync push`), the GUI downloads it itself, updates the on-screen secret list, and triggers a desktop notification.

### B. In the Terminal (`vlt sync listen`) ⌨️
If working without a GUI (Tmux, SSH, Neovim):
```bash
./bin/vlt sync listen --vault vault
```
When a remote client modifies a secret, you will see in the console:
```text
Listening for sync events from server...
✅ Synced with server (seq 2)
```

**Native Desktop Notifications**:
* **macOS**:
  ```text
  vlt — Vault synchronized
  Remote changes applied (sequence 2)
  ```
* **Windows**: Windows 10/11 Toast notification in the bottom right corner.
* **Linux**: Graphical notification via `notify-send`.

---

## Step 6: Multi-Vault Management (`vault` and `work`)

The system supports multiple fully isolated vaults. Each vault has its own sync UUID and independent channel on the server:

```bash
# Sync primary vault
./bin/vlt sync push --vault vault
./bin/vlt sync pull --vault vault

# Sync a secondary vault (e.g. work / teams)
./bin/vlt sync init --vault work --server https://192.168.0.104:8443
./bin/vlt sync push --vault work
./bin/vlt sync pull --vault work

# In the GUI (vlt-gui)
Switch vaults from the 'VAULT' selector in the top left sidebar and use Settings > 'Save & Sync'.
```

### Auto-Recovery and Multi-Vault Resilience
If an active vault in `config.json` is deleted or renamed on disk, both the CLI and GUI detect the absence automatically and **transparently fallback** to `vault.sqlite` or `work.sqlite` without crashing or showing fatal errors.

---

## Step 7: Troubleshooting Guide

| Observed Error | Root Cause | Solution |
| :--- | :--- | :--- |
| `x509: certificate signed by unknown authority` | The client is not using `ca.pem` or the server has an old certificate not signed by the current CA. | Ensure `export VLT_SYNC_CA_CERT=./certs/ca.pem` on the client and restart the container with `server.pem`. |
| `x509: “vlt-sync Server” certificate is not standards compliant` | On macOS, the certificate had a validity > 398 days or wrong `KeyUsage`. | Regenerate certificates with `vlt pki generate` (automatically adjusted to 365 days and `DigitalSignature`). |
| `sync not configured: config key "sync_server_url" not found` | When copying `vault.sqlite` to another machine, the WAL journal files (`vault.sqlite-wal`) were not copied. | Always copy with wildcard: `scp ~/.config/passwd/vault.sqlite* dest:~/.config/passwd/`. |
| `open .../client.pem: no such file or directory` | The `VLT_SYNC_CLIENT_CERT` or `KEY` variables point to a path where files do not exist. | Copy `client.pem` and `client-key.pem` to the path indicated in the variable. |
| `Server registration failed — server may be unreachable` | Port 8443 is not open in the firewall or the container is not running. | Verify with `curl -k https://IP:8443/healthz` and check `docker compose logs`. |
