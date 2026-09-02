# Proposal: Sync Protocol

## Intent

passwd/vlt is local-only — no way to reconcile vaults across devices. Sync enables multi-device use while preserving zero-knowledge: server stores encrypted blobs, sees no plaintext.

## Scope

### In Scope
- `cmd/vlt-sync/` — REST server (standalone, K8s-ready)
- `internal/sync/` — client engine: diff, push, pull, LWW merge, conflict log
- API key auth + mandatory TLS
- `vlt sync` subcommands (push, pull, status, init)
- Server URL + API key in vault config
- Dockerfile for K8s
- Offline-first: vault opens locally, sync on demand

### Out of Scope
Team sharing, E2E sharing, Web UI, federation, mobile, audit sync, WebSockets.

## Capabilities

### New
- `sync-client`: Local engine — diff, push, pull, LWW merge, conflict logging
- `sync-server`: REST server — vault reg, blob store, auth, TLS, health
- `sync-cli`: CLI commands for sync lifecycle

### Modified
None — sync is additive, no existing capability changes.

## Approach

**Data model**: Each secret gets `Version` (monotonic counter) + `SyncedAt`. Server stores vaults as opaque encrypted blobs keyed by vault UUID — no schema awareness.

**Conflict resolution**: LWW per-secret. Higher `SyncedAt` wins. Loser logged for manual review.

**Wire format**: REST over TLS. `POST /v1/vaults/{uuid}/push` (full encrypted snapshot), `POST /v1/vaults/{uuid}/pull` (latest blob), `GET /v1/vaults/{uuid}/status` (version only). JSON + base64.

**Auth**: Pre-shared API key in `Authorization: Bearer <key>`. Generated via `vlt sync init`.

**Storage**: Server SQLite (same driver as client) — one row per vault UUID. K8s PVC for persistence.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `cmd/vlt-sync/` | New | Sync server binary |
| `internal/sync/` | New | Client sync engine |
| `internal/cli/sync.go` | New | CLI subcommands |
| `internal/config/` | Modified | Sync URL + API key |
| `internal/store/` | Modified | Version + SyncedAt |
| `Dockerfile` | New | Multi-stage build |
| `go.mod` | Modified | HTTP router (optional) |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| LWW data loss on concurrent edits | Medium | Log conflicts; `vlt sync status` shows diverged |
| API key compromise | Medium | TLS; key rotation via `rekey`; revoke endpoint |
| Clock skew breaks ordering | Medium | Server timestamp tiebreak; NTP enforced |
| K8s PVC statefulness | Low | Minimal state; volume snapshot backup |

## Rollback Plan

Revert sync commits: delete `cmd/vlt-sync/`, `internal/sync/`, `internal/cli/sync.go`. Revert config/store changes. Existing vaults untouched — zero migration.

## Dependencies

- `crypto/tls`, `net/http` (stdlib)
- `modernc.org/sqlite` (already in use)
- Optional: `go-chi/chi` for routing

## Success Criteria

- [ ] Two devices with same vault produce identical encrypted snapshots after sync
- [ ] Conflicting edits: last writer stored, loser logged
- [ ] Push + pull round-trip preserves all secret metadata
- [ ] Server can't decrypt blobs (zero-knowledge)
- [ ] Vault opens locally without network
- [ ] Docker image builds, runs in K8s with PVC
- [ ] All 13 existing test suites pass
