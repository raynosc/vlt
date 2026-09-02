# TLS Certificates, PKI and Mutual Authentication (mTLS)

[English](TLS-CERTIFICATES.md) | [Español](es/TLS-CERTIFICATES.md)

This guide explains how to generate and manage PEM certificates for `vlt-sync`, the anatomy of each `.pem` file, and how to configure a **Zero-Trust mTLS** (Mutual TLS) architecture.

---

## 1. PEM Certificate Generation with `vlt pki` (Recommended)

`vlt` includes a built-in PKI generator in pure Go using **ECDSA P-256** elliptic curves. No OpenSSL installation or complex configuration files are required.

### A. Generate Complete Certificate Hierarchy (CA + Server + Client)

```bash
# Generates Root CA, Server TLS certificate (with SANs), and your first client cert:
vlt pki generate --out ./certs --hosts "192.168.0.104,localhost,sync.vault.internal" --client "mac-laptop"
```

### B. Issue Client Certificates for Additional Devices

```bash
# Issues a new client certificate signed by your CA (e.g. for a Windows PC):
vlt pki client --ca ./certs/ca.pem --ca-key ./certs/ca-key.pem --name "windows-pc" --out ./certs
```

---

## 2. Anatomy of Generated PEM Files

Running `vlt pki generate` creates 6 files in the output directory:

```
certs/
├── ca.pem              ← Root Certificate Authority (Public)
├── ca-key.pem          ← Root CA Private Key (CONFIDENTIAL / OFFLINE)
├── server.pem          ← Server TLS Certificate with SANs (Public)
├── server-key.pem      ← Server Private Key (Server Secret)
├── client.pem          ← Client mTLS Certificate (Client Public)
└── client-key.pem      ← Client Private Key (Client Secret)
```

| File | Type | Recipient | Purpose |
| :--- | :--- | :--- | :--- |
| **`ca.pem`** | Public Cert | **Server & All Clients** | Root of trust for mutual verification. |
| **`ca-key.pem`** | Private Key | **Admin Only** | Signs new client certificates. Keep offline and secure. |
| **`server.pem`** | Public Cert | **Server Only** | Presented on port `8443` with IP/DNS SANs. |
| **`server-key.pem`** | Private Key | **Server Only** | Server TLS private key. |
| **`client.pem`** | Public Cert | **Client Device** | Client identity presented during TLS handshake. |
| **`client-key.pem`** | Private Key | **Client Device** | Client private key. |

---

## 3. Subject Alternative Names (SANs)

Go enforces strict X.509 SAN validation for all IP addresses and DNS hostnames. When executing:
```bash
vlt pki generate --hosts "192.168.0.104,10.0.0.5,sync.mydomain.com"
```
The PKI engine automatically parses IP vs DNS targets, appends `localhost`, `127.0.0.1`, and `::1`, and injects required X509v3 extensions.

---

## 4. Server Deployment with Zero-Trust mTLS

Start `vlt-sync` requiring mutual client authentication:

```bash
vlt-sync --addr=:8443 \
         --db-path=./sync.db \
         --tls-cert=./certs/server.pem \
         --tls-key=./certs/server-key.pem \
         --tls-client-ca=./certs/ca.pem
```

> [!IMPORTANT]
> Supplying `--tls-client-ca` enables `tls.RequireAndVerifyClientCert`. Any connection without a valid client certificate signed by `ca.pem` is dropped immediately at the TLS layer before processing HTTP requests.