# Tasks: Sync Protocol

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1600 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | Foundation → Server Core → Server HTTP → Client → CLI + Docker |
| Delivery strategy | single-pr |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Foundation (types, crypto, migration) | PR 1 | base=main; ~170 lines |
| 2 | Server core (store, auth, handlers, handler tests) | PR 2 | base=main; ~380 lines |
| 3 | Server runtime (server.go, server_test.go, main.go) | PR 3 | base=main; ~370 lines |
| 4 | Client engine + tests | PR 4 | base=main; ~420 lines |
| 5 | CLI + Dockerfile | PR 5 | base=main; ~255 lines |

## Phase 1: Foundation (Deps: none)

- [x] **T-001** sync-client/server | Create `internal/sync/types.go` with SyncPayload, PushRequest, PullResponse, SyncConflict, VaultStatus structs + json tags. Test: zero-value round-trip via marshal/unmarshal. ~40L
- [x] **T-002** sync-client | Add migration v004 to `internal/store/store.go`: CREATE TABLE sync_conflicts + switch case + schema bump. Test: verify table exists after Init. ~50L
- [x] **T-003** sync-client | Create `internal/sync/crypto.go` — EncryptBlob/DecryptBlob (AES-256-GCM, random nonce). Test: round-trip, wrong-key fails, tampered blob fails. Deps: T-001. ~80L

## Phase 2: Server (Deps: T-001)

- [x] **T-004** sync-server | Create `internal/syncserver/store.go` — SQLite store with vaults + api_keys tables, CRUD, seq increment. Test: in-memory SQLite CRUD via store_test.go companion. ~130L
- [x] **T-005** sync-server | Create `internal/syncserver/auth.go` — Bearer token middleware (SHA-256 hash → lookup). Test: valid key passes, invalid key 403, missing 401. Deps: T-004. ~60L
- [x] **T-006** sync-server | Create `internal/syncserver/handler.go` — 7 handlers: register, revoke, push, pull, status, healthz, readyz. Test: httptest.Server round-trips in server_test.go. Deps: T-004, T-005. ~220L
- [x] **T-007** sync-server | Create `internal/syncserver/server.go` — NewServer with TLS config, ListenAndServe graceful shutdown. Test: server starts and healthz responds. Deps: T-006. ~90L
- [x] **T-008** sync-server | Create `cmd/vlt-sync/main.go` — flag/env parsing (addr, data-dir, tls-cert/key), server start. Test: flag defaults. Deps: T-007. ~70L

## Phase 3: Client Engine (Deps: T-001, T-003)

- [x] **T-009** sync-client | Create `internal/sync/client.go` — NewClient, Push (List→Marshal→Encrypt→POST→save seq), Pull (GET→Decrypt→Unmarshal→LWW merge→store→log conflicts→save seq), Status. Test: table-driven LWW scenarios (local-newer, remote-newer, same-ts, new secret, empty vault). ~220L
- [x] **T-010** sync-client | Create `internal/sync/client_test.go` — integration: init→add secret→push→pull→verify, using httptest.Server + real SQLite both sides. Deps: T-009, T-006 (needs handler). ~230L

## Phase 4: CLI (Deps: T-002, T-009)

- [x] **T-011** sync-cli | Create `internal/cli/sync.go` — `vlt sync init --server`, `vlt sync push`, `vlt sync pull`, `vlt sync status`. Test: mockStore + executeCmd for each subcommand output. ~230L
- [x] **T-012** sync-cli | Edit `internal/cli/root.go` — add `rootCmd.AddCommand(newSyncCmd())`. ~5L

## Phase 5: Deployment (Deps: T-008)

- [x] **T-013** | Create `Dockerfile` — multi-stage Go build → alpine, expose port, health check. ~30L
