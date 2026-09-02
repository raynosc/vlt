# Design: Sync Protocol

## Technical Approach

Full encrypted vault snapshot sync. Client serializes all secrets (each already individually encrypted with AES-256-GCM) into JSON, encrypts the entire bundle with a dedicated AES-256 sync key, and ships the opaque blob to the server. Server stores per-vault blob + monotonic sequence number — sees zero plaintext. Pull decrypts, deserializes, and LWW-merges per secret using `updated_at`. Offline-first: vault opens locally without network.

## Architecture Decisions

| Decision | Options | Choice | Rationale |
|----------|---------|--------|-----------|
| Sync unit | per-change delta, full snapshot | Full encrypted snapshot | Simpler protocol, zero-knowledge trivially, no server-side merge logic |
| Conflict resolution | MVCC, CRDT, LWW timestamps | LWW `updated_at` | Matches existing Secret.UpdatedAt field; no new ordering primitives |
| Vault identity | DNS-based, user-chosen, UUID v4 | UUID v4 in config table | Already have `newUUID()` in store; idempotent, no server coordination |
| Blob encryption | Master-key-derived HKDF, dedicated random key | Dedicated AES-256 key in config table | Offline-first: sync key available without re-prompting master password; HKDF derivation adds no security benefit here |
| Server DB | standalone file per vault, SQLite | SQLite (same `modernc.org/sqlite`) | Zero new deps, same driver as client; single table per vault UUID |
| HTTP router | `go-chi/chi`, stdlib `net/http` mux | `net/http` (Go 1.22+ pattern routing) | Go 1.26 has route patterns; avoids adding `chi` dep for 5 endpoints |
| API key hashing | bcrypt, SHA-256, argon2 | SHA-256 | Keys are random 256-bit CSPRNG output — no need for slow hash; fast path for every request |

## Data Flow

```
CLIENT PUSH:
  SQLStore.List() → secret.Secret[]
  json.Marshal(secrets) → plaintext
  sync.EncryptBlob(plaintext, syncKey) → ciphertext
  POST /v1/vaults/{uuid}/push { seq: N, blob: base64(ciphertext) }
  SERVER: validate API key, verify seq > stored seq, store blob, inc seq
  Response: { seq: N+1, status: "ok" }
  Client: ConfigSet("last_sync_seq", N+1)

CLIENT PULL:
  GET /v1/vaults/{uuid}/pull?since=N
  SERVER: auth check, read latest blob + seq
  Response: { seq: M, blob: base64(ciphertext) }
  Client: sync.DecryptBlob(ciphertext, syncKey) → plaintext
  json.Unmarshal → remote.Secret[]
  For each secret:
    local ← GetByName(remote.Name)
    if remote.UpdatedAt > local.UpdatedAt: upsert (Store)
    else: skip (local is newer)
    Conflicts logged to sync_losers table
  ConfigSet("last_sync_seq", M)

VAULT INIT:
  vlt sync init --server https://sync.example.com
  → crypto/rand 32B → sync_encryption_key (AES-256)
  → crypto/rand 32B → raw_api_key
  → SHA-256(raw_api_key) → key_hash
  → PUT /v1/auth/register { vault_uuid, key_hash }
  → ConfigSet("sync_server_url", url)
  → ConfigSet("vault_uuid", uuid)
  → ConfigSet("api_key", raw_api_key)        // plaintext for auth header
  → ConfigSet("sync_encryption_key", key)     // plaintext for blob encrypt
  → Print API key for server-side config
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `internal/sync/types.go` | Create | SyncPayload, PushRequest, PullResponse, Conflict types |
| `internal/sync/crypto.go` | Create | EncryptBlob, DecryptBlob (AES-256-GCM with sync key) |
| `internal/sync/client.go` | Create | SyncClient: Push, Pull, Status, Merge (LWW reconcile) |
| `internal/sync/client_test.go` | Create | LWW merge edge cases, encrypt/decrypt round-trip |
| `internal/syncserver/store.go` | Create | SQLite storage: vaults, api_keys tables + CRUD |
| `internal/syncserver/auth.go` | Create | API key middleware (Bearer token → SHA-256 → lookup) |
| `internal/syncserver/handler.go` | Create | HTTP handlers: push, pull, status, register, revoke, health |
| `internal/syncserver/server.go` | Create | NewServer, TLS config, ListenAndServe |
| `internal/syncserver/server_test.go` | Create | Handler tests with in-memory SQLite |
| `cmd/vlt-sync/main.go` | Create | Server entry point: flag/env parsing, server start |
| `internal/cli/sync.go` | Create | `vlt sync init`, `vlt sync push`, `vlt sync pull`, `vlt sync status` |
| `internal/cli/root.go` | Modify | Add `root.AddCommand(newSyncCmd())` |
| `internal/store/store.go` | Modify | Migration v004: newVault, newApiKey, newSyncKey, newLastSyncSeq config keys |
| `Dockerfile` | Create | Multi-stage Go build → distroless scratch |
| `go.mod` | Modify | No new direct deps (all stdlib) |

## Interfaces / Contracts

```go
// internal/sync/types.go
type SyncPayload struct {
    Secrets []secret.Secret `json:"secrets"`
}

type SyncConflict struct {
    Name      string    `json:"name"`
    LocalTS   time.Time `json:"local_updated_at"`
    RemoteTS  time.Time `json:"remote_updated_at"`
    Resolved  string    `json:"resolution"` // "local_wins" | "remote_wins"
}

type PushRequest struct {
    VaultUUID string `json:"vault_uuid"`
    Seq       int64  `json:"seq"`
    Blob      []byte `json:"blob"` // base64-encoded ciphertext
}

type PullResponse struct {
    Seq  int64  `json:"seq"`
    Blob []byte `json:"blob"` // base64-encoded ciphertext
}

// internal/sync/client.go
type Client struct {
    store     *store.SQLStore
    serverURL string
    vaultUUID string
    apiKey    string
    syncKey   []byte // 32 bytes
}

func NewClient(s *store.SQLStore) (*Client, error)
func (c *Client) Push() (seq int64, err error)
func (c *Client) Pull() (conflicts []SyncConflict, err error)
func (c *Client) Status() (*VaultStatus, error)
```

### Migration v004 (client store)

```sql
-- No schema changes to secrets table — uses existing updated_at for LWW.
-- Sync config keys stored in existing `config` table:
--   "vault_uuid"         → vault UUID string
--   "sync_server_url"    → server base URL
--   "api_key"            → raw API key (stored unencrypted; vault access controls read)
--   "sync_encryption_key" → 32-byte AES key (raw bytes)
--   "last_sync_seq"      → int64 string

-- New table for conflict tracking:
CREATE TABLE IF NOT EXISTS sync_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_name TEXT NOT NULL,
    conflict_time TEXT NOT NULL DEFAULT (datetime('now')),
    local_json TEXT NOT NULL,
    remote_json TEXT NOT NULL,
    resolution TEXT NOT NULL DEFAULT 'pending'
);
```

### Server Storage (syncserver/store.go)

```sql
CREATE TABLE IF NOT EXISTS vaults (
    vault_uuid TEXT PRIMARY KEY,
    encrypted_blob BLOB,
    seq INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    vault_uuid TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (vault_uuid) REFERENCES vaults(vault_uuid)
);
```

### API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/auth/register` | None | Register new vault + API key |
| POST | `/v1/auth/revoke` | Bearer | Revoke API key |
| POST | `/v1/vaults/{uuid}/push` | Bearer | Push encrypted snapshot |
| GET | `/v1/vaults/{uuid}/pull` | Bearer | Pull latest snapshot |
| GET | `/v1/vaults/{uuid}/status` | Bearer | Get vault metadata |
| GET | `/healthz` | None | Liveness probe |
| GET | `/readyz` | None | Readiness probe |

## Testing Strategy (STRICT TDD)

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit — sync crypto | EncryptBlob/DecryptBlob round-trip, wrong key fails, tampered blob fails | Pure function, test vectors |
| Unit — sync merge | Local-newer, remote-newer, same-timestamp, new secret, deleted secret, empty vault | Table-driven LWW scenarios |
| Unit — server store | Vault CRUD, seq increment, api key CRUD, revoke | In-memory SQLite |
| Integration — push/pull | Full round-trip: init → add secret → push → pull → verify decrypted matches | Real SQLite on both sides, test HTTP server |
| CLI — sync init | Config keys written correctly, API key printed | `mockStore` + `executeCmd` pattern |
| Migration — v004 | Sync config keys can be stored/retrieved, sync_conflicts table exists | Existing migration test pattern |
| E2E — Docker | Binary starts, healthz returns 200, push/pull round-trip | Docker compose test |

## Migration / Rollout

No data migration for existing vaults. Sync config keys (`vault_uuid`, `sync_server_url`, etc.) are written only when `vlt sync init` runs. Existing vaults work without changes. New `sync_conflicts` table created by migration v004. Server is a standalone binary — deploy independently.

## Open Questions

- [ ] Confirm: should sync key be protected via HKDF derivation from master password instead of stored raw? Tradeoff: better security (no plaintext key in DB) vs. requiring unlock before each sync (breaks offline usability for sync scheduling).
- [ ] Should `vlt sync push` require the vault to be unlocked (key in memory)? Or auto-unlock with keychain?
