---
name: vlt-sync-ops
description: Operations guide for vlt-sync (deployment in Docker, Compose, Kubernetes, TLS, and real-time SSE sync).
---

# vlt Sync Operations Skill

This skill provides step-by-step instructions for running, testing, and debugging the `vlt-sync` server and client synchronization protocol.

---

## 1. Sync Protocol Architecture

* **Zero-Knowledge**: Client encrypts the entire vault payload with `sync_encryption_key` (AES-256-GCM + AAD). Server only stores `(vault_uuid, seq, encrypted_blob, updated_at)`.
* **CAS (Compare-and-Swap)**: Server enforces monotonic sequence numbers (`seq`). On push mismatch, returns HTTP 409 Conflict.
* **Real-time SSE (`/v1/vaults/{uuid}/events`)**: Clients maintain an open HTTP connection to receive `event: vault_updated` instantly when a push occurs.
* **Anti-Rollback**: Client pins `registration_seq` and refuses pull payloads with `seq < effectiveSeq`.

---

## 2. Docker & Compose Operations

```bash
# Build the Docker image
docker build -t vlt-sync .

# Run with docker compose (uses ./data and ./certs)
docker compose up -d

# Inspect logs
docker compose logs -f

# Check health endpoint
curl -k https://localhost:8443/healthz
```

---

## 3. Client Synchronization Commands

```bash
# Initialize sync on local vault (generates UUID, sync key, and registers with server)
vlt sync init --server https://sync.example.com

# For local self-signed testing:
vlt sync init --server https://192.168.0.104:8443 --insecure

# Push local changes to server
vlt sync push

# Pull and merge remote changes
vlt sync pull

# Listen in real-time with background auto-pull and desktop notifications
vlt sync listen
```

---

---

## 4. Zero-Trust mTLS Deployment & PKI

`vlt` includes a built-in PKI generator to establish end-to-end mutual authentication without requiring external tools like OpenSSL.

### A. Generate mTLS PKI Certificates
```bash
# Generate CA, server certificates, and initial client certificate in one command:
vlt pki generate --out ./certs --hosts "192.168.0.104,sync.local,localhost" --client "mac-laptop"

# Issue additional client certificates for other devices (e.g. Windows PC):
vlt pki client --ca ./certs/ca.pem --ca-key ./certs/ca-key.pem --name "windows-pc" --out ./certs
```

Generated files:
* `ca.pem` & `ca-key.pem` — Root Certificate Authority.
* `server.pem` & `server-key.pem` — Server TLS certificate with IP/DNS SANs.
* `client.pem` & `client-key.pem` — Client mTLS certificates.

### B. Run `vlt-sync` with mTLS Enforced
```bash
# The server will REJECT any connection whose client does not provide a valid certificate signed by ca.pem:
vlt-sync --addr=:8443 \
         --tls-cert=./certs/server.pem \
         --tls-key=./certs/server-key.pem \
         --tls-client-ca=./certs/ca.pem
```

### C. Connect Clients with mTLS
```bash
export VLT_SYNC_CA_CERT=./certs/ca.pem
export VLT_SYNC_CLIENT_CERT=./certs/client.pem
export VLT_SYNC_CLIENT_KEY=./certs/client-key.pem

# Initialize sync over mTLS
vlt sync init --server https://192.168.0.104:8443
```

---

---

## 5. Multi-Vault Sync Operations

To synchronize a secondary vault (e.g. `1password`):
```bash
# Initialize sync for a specific vault
vlt sync init --vault 1password --server https://192.168.0.104:8443

# Push and Pull with explicit vault target
vlt sync push --vault 1password
vlt sync pull --vault 1password

# Real-time listener for specific vault
vlt sync listen --vault 1password
```

---

## 6. Windows Client Sync Operations

Windows users run `vlt.exe` with PowerShell:
```powershell
# Initialize sync with mTLS certificates
.\vlt.exe sync init `
  --server "https://192.168.0.104:8443" `
  --tls-ca "C:\Tools\vlt\certs\ca.pem" `
  --tls-cert "C:\Tools\vlt\certs\windows-pc.pem" `
  --tls-key "C:\Tools\vlt\certs\windows-pc-key.pem"

# Run real-time sync with native Windows Toast notifications
.\vlt.exe sync listen
```

---

## 7. Kubernetes Deployment

Production manifest is available in [`deploy/k8s/vlt-sync.yaml`](file:///deploy/k8s/vlt-sync.yaml).
* **Storage**: Single-pod Deployment/StatefulSet with `ReadWriteOnce` PVC for SQLite.
* **Probes**: `livenessProbe` and `readinessProbe` checking `/healthz`.
* **Security**: Non-root UID 1000.
