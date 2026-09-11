# Complete Architecture of vlt — Mermaid Diagrams

[English](ARCHITECTURE-MERMAID.md) | [Español](es/ARCHITECTURE-MERMAID.md)

This document contains the comprehensive visual representation of the **`vlt`** system architecture, covering everything from the user interfaces and local cryptographic subsystem to the mTLS certificate PKI infrastructure and the real-time Zero-Knowledge synchronization protocol.

---

## 1. General System Architecture

```mermaid
graph TB
    subgraph CLIENTES ["Client Ecosystem (Cross-platform)"]
        GUI["vlt-gui (Desktop Fyne v2)<br/>macOS / Linux / Windows"]
        TUI["vlt-tui (Terminal Bubble Tea)"]
        CLI["vlt (CLI Cobra Engine)"]
        QUICK["vlt-quick (Spotlight Popup)"]
        DAEMON["vlt daemon (Unix Domain Socket / IPC)"]
        
        QUICK -->|IPC Socket| DAEMON
        DAEMON -->|Store & Key| CORE
        GUI -->|Direct Binding| CORE
        TUI -->|Direct Binding| CORE
        CLI -->|Direct Binding| CORE
    end

    subgraph CORE ["Local Engine and Cryptography (internal/)"]
        KDF["Argon2id KDF<br/>(64MB RAM, 3 iters, 4 threads)"]
        AES["AES-256-GCM + AAD Engine<br/>(Nonce 12B + Tag 16B)"]
        BLIND["HMAC-SHA256 Blind Index<br/>(name_lookup)"]
        ZERO["crypto.Zeroize()<br/>(RAM Sanitization)"]
        OTP["RFC 6238 TOTP / RFC 4226 HOTP<br/>(QR Code Parser)"]
        WATCH["Watchtower Security Engine<br/>(Weak, Reused, Expired, Pwned)"]
        PKI_GEN["PKI Engine (ECDSA P-256)<br/>vlt pki generate / client"]
        
        KDF --> AES
        KDF --> BLIND
    end

    subgraph LOCAL_STORE ["Local Storage (~/.config/passwd/)"]
        CONFIG_JSON["config.json<br/>(active_vault, vault_path)"]
        SQLITE["SQLite Schema v7 (WAL Mode)<br/>• encrypted_value (AES)<br/>• encrypted_name (AES)<br/>• name_lookup (UNIQUE HMAC)<br/>• encrypted_metadata (AES)<br/>• deleted_at (Tombstones)"]
        
        CORE --> SQLITE
        CORE --> CONFIG_JSON
    end

    subgraph PKI_CERTS ["PKI Infrastructure / mTLS (certs/)"]
        CA["Root CA (ca.pem + ca-key.pem)<br/>Validity: 10 years"]
        SRV_CERT["Server Cert (server.pem + server-key.pem)<br/>Validity: 365 days (RFC 5280)<br/>SANs: IP + DNS"]
        CLI_CERT1["Client Cert Mac (client.pem + client-key.pem)"]
        CLI_CERT2["Client Cert Windows (windows-pc.pem + key)"]
        
        CA -->|Signs| SRV_CERT
        CA -->|Signs| CLI_CERT1
        CA -->|Signs| CLI_CERT2
    end

    subgraph SYNC_TRANSPORT ["Secure Transport Channel"]
        TLS_PIPE["mTLS Mutual Handshake (TLS 1.3 / HTTP/2)<br/>ClientAuth: RequireAndVerifyClientCert"]
    end

    subgraph SYNC_SERVER ["Synchronization Server (vlt-sync on Docker / VM)"]
        ROUTER["HTTP REST Router (Port 8443)"]
        AUTH["Bearer API Key Validator<br/>(SHA-256 blind hash)"]
        CAS["Atomic CAS Engine<br/>(Monotonic sequence seq)"]
        SSE["SSE Broadcaster (/v1/vaults/{uuid}/events)<br/>Real-Time Notifications"]
        SERVER_DB["Blind Storage SQLite (/data/sync.db)<br/>• vault_uuid<br/>• seq<br/>• encrypted_blob<br/>• key_hash"]
        
        ROUTER --> AUTH
        AUTH --> CAS
        CAS --> SERVER_DB
        CAS --> SSE
    end

    CLI_CERT1 -.->|Presents Cert| TLS_PIPE
    CLI_CERT2 -.->|Presents Cert| TLS_PIPE
    SRV_CERT -.->|Presents Cert| TLS_PIPE
    CA -.->|Validates both| TLS_PIPE

    CORE -->|Encrypted SyncPayload| TLS_PIPE
    TLS_PIPE --> ROUTER
    SSE -.->|vault_updated| GUI
    SSE -.->|vault_updated| CLI
```

---

## 2. Cryptographic Derivation and Local Storage Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as Interface (CLI / GUI / TUI)
    participant KDF as Argon2id Engine
    participant Crypto as AES-256-GCM / HMAC
    participant RAM as Volatile Memory
    participant DB as SQLite (Schema v7)

    User->>UI: Enters Master Password
    UI->>DB: Reads salt and verify_hash (config table)
    UI->>KDF: Derives 32 byte key (64MB RAM, 3 iters)
    KDF->>RAM: Stores derivedKey
    
    rect rgb(25, 45, 60)
        Note over UI,Crypto: Secret Encryption
        UI->>Crypto: Encrypts payload with derivedKey + AAD
        Crypto->>Crypto: Computes name_lookup = HMAC(derivedKey, "passwd.name." + name)
        Crypto->>DB: INSERT / UPDATE in SQLite (Ciphertext Only)
    end
    
    UI->>RAM: crypto.Zeroize(masterPassword)
    Note over RAM: Plaintext password is destroyed in RAM
```

---

## 3. Complete mTLS Synchronization and Real-Time Events Flow

```mermaid
sequenceDiagram
    autonumber
    participant Mac as Client 1 (Mac Laptop)
    participant Server as vlt-sync Server (192.168.0.104:8443)
    participant Win as Client 2 (Windows PC / VM)

    Note over Mac,Server: 1. mTLS Negotiation (Mutual Handshake)
    Mac->>Server: ClientHello + Presents client.pem
    Server->>Mac: ServerHello + Presents server.pem
    Server-->>Server: Validates client.pem against ca.pem
    Mac-->>Mac: Validates server.pem against ca.pem + SANs
    Note over Mac,Server: mTLS Tunnel Established (TLS 1.3)

    Note over Mac,Server: 2. Active Event Listening
    Mac->>Server: GET /v1/vaults/{uuid}/events (SSE Stream)
    Server-->>Mac: Connection opened (200 OK text/event-stream)

    Note over Win,Server: 3. Modification from Client 2
    Win->>Win: Adds/Edits local secret
    Win->>Server: POST /v1/vaults/{uuid}/push (Payload encrypted with sync_encryption_key)
    Server->>Server: Increments atomic sequence (seq: 2)
    Server->>Server: Saves encrypted blob in /data/sync.db
    Server-->>Win: 200 OK (Pushed seq 2)

    Note over Server,Mac: 4. Real-Time Notification and Auto-Pull
    Server->>Mac: event: vault_updated {"seq": 2}
    Mac->>Server: GET /v1/vaults/{uuid}/pull
    Server-->>Mac: Returns encrypted SyncPayload (seq 2)
    Mac->>Mac: Decrypts with sync_encryption_key + LWW Merge
    Mac->>Mac: macOS native notification ("vlt — Vault synchronized")
```
