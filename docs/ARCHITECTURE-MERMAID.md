# Arquitectura Completa de vlt — Diagramas Mermaid

Este documento contiene la representación visual exhaustiva de la arquitectura del sistema **`vlt`**, abarcando desde las interfaces de usuario y el subsistema criptográfico local hasta la infraestructura PKI de certificados mTLS y el protocolo de sincronización Zero-Knowledge en tiempo real.

---

## 1. Arquitectura General del Sistema

```mermaid
graph TB
    subgraph CLIENTES ["Ecosistema de Clientes (Multiplataforma)"]
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

    subgraph CORE ["Motor Local y Criptografía (internal/)"]
        KDF["Argon2id KDF<br/>(64MB RAM, 3 iters, 4 hilos)"]
        AES["AES-256-GCM + AAD Engine<br/>(Nonce 12B + Tag 16B)"]
        BLIND["HMAC-SHA256 Blind Index<br/>(name_lookup)"]
        ZERO["crypto.Zeroize()<br/>(RAM Sanitization)"]
        OTP["RFC 6238 TOTP / RFC 4226 HOTP<br/>(QR Code Parser)"]
        WATCH["Watchtower Security Engine<br/>(Weak, Reused, Expired, Pwned)"]
        PKI_GEN["PKI Engine (ECDSA P-256)<br/>vlt pki generate / client"]
        
        KDF --> AES
        KDF --> BLIND
    end

    subgraph LOCAL_STORE ["Almacenamiento Local (~/.config/passwd/)"]
        CONFIG_JSON["config.json<br/>(active_vault, vault_path)"]
        SQLITE["SQLite Schema v7 (WAL Mode)<br/>• encrypted_value (AES)<br/>• encrypted_name (AES)<br/>• name_lookup (UNIQUE HMAC)<br/>• encrypted_metadata (AES)<br/>• deleted_at (Tombstones)"]
        
        CORE --> SQLITE
        CORE --> CONFIG_JSON
    end

    subgraph PKI_CERTS ["Infraestructura PKI / mTLS (certs/)"]
        CA["Root CA (ca.pem + ca-key.pem)<br/>Vigencia: 10 años"]
        SRV_CERT["Server Cert (server.pem + server-key.pem)<br/>Vigencia: 365 días (RFC 5280)<br/>SANs: IP + DNS"]
        CLI_CERT1["Client Cert Mac (client.pem + client-key.pem)"]
        CLI_CERT2["Client Cert Windows (windows-pc.pem + key)"]
        
        CA -->|Firma| SRV_CERT
        CA -->|Firma| CLI_CERT1
        CA -->|Firma| CLI_CERT2
    end

    subgraph SYNC_TRANSPORT ["Canal de Transporte Seguro"]
        TLS_PIPE["mTLS Mutual Handshake (TLS 1.3 / HTTP/2)<br/>ClientAuth: RequireAndVerifyClientCert"]
    end

    subgraph SYNC_SERVER ["Servidor de Sincronización (vlt-sync en Docker / VM)"]
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

    CLI_CERT1 -.->|Presenta Cert| TLS_PIPE
    CLI_CERT2 -.->|Presenta Cert| TLS_PIPE
    SRV_CERT -.->|Presenta Cert| TLS_PIPE
    CA -.->|Valida a ambos| TLS_PIPE

    CORE -->|SyncPayload Cifrado| TLS_PIPE
    TLS_PIPE --> ROUTER
    SSE -.->|vault_updated| GUI
    SSE -.->|vault_updated| CLI
```

---

## 2. Flujo de Derivación Criptográfica y Almacenamiento Local

```mermaid
sequenceDiagram
    autonumber
    actor Usuario
    participant UI as Interfaz (CLI / GUI / TUI)
    participant KDF as Argon2id Engine
    participant Crypto as AES-256-GCM / HMAC
    participant RAM as Memoria Volátil
    participant DB as SQLite (Schema v7)

    Usuario->>UI: Ingresa Master Password
    UI->>DB: Lee salt y verify_hash (tabla config)
    UI->>KDF: Deriva clave de 32 bytes (64MB RAM, 3 iters)
    KDF->>RAM: Almacena derivedKey
    
    rect rgb(25, 45, 60)
        Note over UI,Crypto: Cifrado de Secreto
        UI->>Crypto: Cifra payload con derivedKey + AAD
        Crypto->>Crypto: Calcula name_lookup = HMAC(derivedKey, "passwd.name." + name)
        Crypto->>DB: INSERT / UPDATE en SQLite (Solo Ciphertext)
    end
    
    UI->>RAM: crypto.Zeroize(masterPassword)
    Note over RAM: La contraseña en texto plano se destruye en RAM
```

---

## 3. Flujo Completo de Sincronización mTLS y Eventos en Tiempo Real

```mermaid
sequenceDiagram
    autonumber
    participant Mac as Cliente 1 (Mac Laptop)
    participant Server as Servidor vlt-sync (192.168.0.104:8443)
    participant Win as Cliente 2 (Windows PC / VM)

    Note over Mac,Server: 1. Negociación mTLS (Handshake Mutuo)
    Mac->>Server: ClientHello + Presenta client.pem
    Server->>Mac: ServerHello + Presenta server.pem
    Server-->>Server: Valida client.pem contra ca.pem
    Mac-->>Mac: Valida server.pem contra ca.pem + SANs
    Note over Mac,Server: Túnel mTLS Establecido (TLS 1.3)

    Note over Mac,Server: 2. Escucha Activa de Eventos
    Mac->>Server: GET /v1/vaults/{uuid}/events (SSE Stream)
    Server-->>Mac: Conexión abierta (200 OK text/event-stream)

    Note over Win,Server: 3. Modificación desde Cliente 2
    Win->>Win: Agrega/Edita secreto local
    Win->>Server: POST /v1/vaults/{uuid}/push (Payload cifrado con sync_encryption_key)
    Server->>Server: Incrementa secuencia atómica (seq: 2)
    Server->>Server: Guarda blob cifrado en /data/sync.db
    Server-->>Win: 200 OK (Pushed seq 2)

    Note over Server,Mac: 4. Notificación y Auto-Pull en Tiempo Real
    Server->>Mac: event: vault_updated {"seq": 2}
    Mac->>Server: GET /v1/vaults/{uuid}/pull
    Server-->>Mac: Retorna SyncPayload cifrado (seq 2)
    Mac->>Mac: Descifra con sync_encryption_key + Fusión LWW
    Mac->>Mac: Notificación nativa macOS ("vlt — Bóveda sincronizada")
```
