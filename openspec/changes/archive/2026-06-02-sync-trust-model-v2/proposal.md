# Proposal: Sync Trust Model v2

## Intent

Close the remaining E2E-sync trust-model gaps from the security audit. The whole point of E2E
encryption is to **not trust the sync server**, so each gap matters under a malicious or
compromised-server threat model: tombstones (H2) prevent forced secret resurrection, the
fresh-device anchor (F1/F2) prevents serving stale blobs, and the nil-AAD gate (F3) prevents
silently undoing key-name binding on migrated vaults. F4 is a UX lost-update, not a security
exploit, and is the lowest priority.

## Scope

### In Scope

- **H2 Tombstones (Option A)**: `DeletedAt *time.Time` (json omitempty) on `Secret`; LWW treats it
  as a write; `store.SoftDelete(name)`; `List`/`GetByName` filter deleted; 30-day purge **client-side, post-merge only**. Schema v6 adds `deleted_at`.
- **F1/F2 Fresh-device anchor (registration_seq + pre-flight)**: add `VaultSeq` to
  `RegisterResponse`; client stores `registration_seq`; Pull uses `max(lastSeq, registrationSeq)`.
  For a brand-new vault (seq=0), pre-flight GET to anchor before accepting the pull.
- **F3 nil-AAD version gate (config_format_version=2)**: write `=2` only after BOTH `api_key` and
  `sync_encryption_key` re-wrap succeed; `UnwrapConfigValue` skips the nil-AAD fallback when `>= 2`.
- **F4 Push 409 retry**: auto-pull + retry on CAS conflict, capped at max 1 retry.

### Out of Scope

- Server-side history / versioning (server stays a dumb opaque-blob store).
- Signed-seq anti-rollback schemes — break zero-knowledge (client would need the server key).
- H5 macOS biometrics — separate domain.

## Calibration

F4 is **NOT** a security exploit. The server CAS invariant guarantees a successful push assigns
`lastSeq+1` — exactly the predicted AAD seq — so the vault never becomes unreadable. A partial
failure is a lost-update recovered by the next pull. Lowest priority, smallest fix.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `sync-client`: tombstone-aware LWW merge, `registration_seq` anti-rollback anchor, fresh-device
  pre-flight seq anchoring, push 409 auto-pull retry.
- `sync-security`: `config_format_version=2` gate disabling nil-AAD fallback on migrated vaults;
  rollback resistance on fresh devices.
- `cli-store-robustness`: schema v6 (`deleted_at`), soft-delete + filtered reads, client-side purge horizon.
- `sync-server`: `VaultSeq` in `RegisterResponse` / pre-flight seq read (opaque-blob model preserved).

## Approach

Apply the exploration's recommended option per item. Backward-compat rides on `json omitempty`: a
pre-tombstone client ignores `deleted_at` and resurrects locally, resolved on upgrade when the
tombstone wins by LWW. Purge horizon runs client-side post-merge only — never on the server.
`config_format_version=2` is written only after both re-wraps succeed (atomic invariant).

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/secret/secret.go` | Modified | Add `DeletedAt *time.Time` (omitempty) |
| `internal/store/store.go` | Modified | Schema v6 `deleted_at`; `SoftDelete`; filtered `List`/`GetByName` |
| `internal/sync/client.go` | Modified | Tombstone LWW merge; `max(lastSeq, registrationSeq)`; pre-flight; 409 retry |
| `internal/sync/secrets.go` | Modified | `UnwrapConfigValue` version-gated fallback |
| `internal/sync/types.go` | Modified | `VaultSeq` on `RegisterResponse`; payload version |
| `internal/syncserver/store.go` | Modified | Surface `VaultSeq` / pre-flight seq read |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| `cert-parsing` Phase 2-3 schema conflict (also touches `store.go` + `Secret`) | Med | **Prerequisite check before apply**: coordinate the v6 bump; rebase if cert-parsing lands first |
| Old-client wire compat resurrects deleted secret | Low | `omitempty`; tombstone wins by LWW on upgrade |
| Purge runs server-side by mistake | Low | Enforce client-side post-merge only |
| F4 retry loop | Low | Cap at 1 retry |
| `config_format_version=2` written before both re-wraps | Low | Write only after BOTH succeed |

## Delivery Strategy

`delivery_strategy = ask-on-risk` (default). Recommended split, **chained / stacked PRs**:

- **PR1** = H2 + F1/F2 (~380 lines — borderline 400-line review budget).
- **PR2** = F3 + F4 (low effort).

PR1 is at the budget edge; if RED tests push it over 400, prefer stacking H2 and F1/F2 as separate slices.

## Rollback Plan

Revert per PR. Schema v6 migration is additive (`deleted_at DEFAULT NULL`) — a rollback to v5 code
ignores the column harmlessly. No data migration of existing rows. `config_format_version` left at 1
falls back to prior behavior. Revert `VaultSeq`/retry purely client-side, no server state change.

## Dependencies

- **Prerequisite**: confirm `cert-parsing` Phase 2-3 schema state before apply (shared `store.go` / `Secret`).
- STRICT TDD active (`go test ./...`) — downstream phases MUST follow RED → GREEN → REFACTOR. All new tests pure-Go (no CGO).

## Success Criteria

- [ ] Deleted secret stays deleted across pull; malicious replay of pre-delete blob cannot resurrect it.
- [ ] Fresh device rejects a stale blob via `max(lastSeq, registrationSeq)` + pre-flight anchor.
- [ ] Migrated vault (`config_format_version=2`) never falls back to nil-AAD decryption.
- [ ] Push 409 auto-pulls and retries once; vault stays readable.
- [ ] `go test ./...` green; schema at v6.
