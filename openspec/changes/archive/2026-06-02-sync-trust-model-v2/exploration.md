# Exploration — sync-trust-model-v2

Close the remaining E2E-sync trust-model gaps left open by the security audit:
H2 (tombstones), F1/F2 (anti-rollback on fresh device), F3 (nil-AAD fallback gate), F4 (push seq prediction).

## Current model

Snapshot-blob: the client serializes all secrets, encrypts the JSON with AES-256-GCM
(AAD `{vaultUUID}|{seq}|v1`), and ships it to the server, which stores one blob per vault
plus a CAS sequence number. The server never sees plaintext.

| File | Role |
|------|------|
| `internal/secret/secret.go` | `Secret` has `CreatedAt`/`UpdatedAt`, **no `DeletedAt`** |
| `internal/sync/types.go` | `SyncPayload{Secrets}` — no version, no tombstones |
| `internal/sync/client.go` | `Push` (~L114) AAD uses predicted `lastSeq+1`; `Pull` (~L217/265) check `pullResp.Seq < lastSeq`; `mergeSecrets` (~L400) add/keep only |
| `internal/sync/secrets.go` | `UnwrapConfigValue` nil-AAD fallback, no version gate |
| `internal/store/store.go` | `CurrentSchemaVersion=5`, config table holds `last_sync_seq` |
| `internal/syncserver/store.go` | `VaultRow` opaque blob + seq |

## Per-item findings

### H2 — Tombstones (HIGH)
`mergeSecrets` never deletes: a secret deleted on device A reappears on device B's next pull;
a malicious server can force resurrection by serving the pre-delete blob.
**Recommended (Option A):** add `DeletedAt *time.Time` (json omitempty) to `Secret`; LWW treats
`DeletedAt` as the last write; `store.SoftDelete(name)`; `List`/`GetByName` filter deleted;
30-day purge horizon applied **client-side, post-merge only**. Schema v6:
`ALTER TABLE secrets ADD COLUMN deleted_at TEXT DEFAULT NULL`. Wire backward-compat via omitempty.

### F1/F2 — Anti-rollback on a fresh device (HIGH)
`Pull` check is `pullResp.Seq < lastSeq` with `lastSeq=0` on a new device → a malicious server
can serve an old blob. Note: changing `<` to `<=` is **wrong** (Pull writes `last_sync_seq`; a
no-change re-pull returns the same seq → would be rejected).
**Recommended (Option E + D):** add `VaultSeq` to `RegisterResponse`; client stores
`registration_seq`; Pull uses `max(lastSeq, registrationSeq)`. For a brand-new vault (seq=0),
add a pre-flight GET to anchor the seq before accepting the pull. Signed-seq rejected (breaks
zero-knowledge — client would need the server key).

### F3 — nil-AAD fallback gate (MEDIUM)
`UnwrapConfigValue` always falls back to nil-AAD decryption, silently undoing the M1 key-name
binding even on migrated vaults.
**Recommended (Option A):** add `config_format_version` config key; write `=2` only after BOTH
`api_key` and `sync_encryption_key` are re-wrapped successfully; `UnwrapConfigValue` takes a
`configVersion` param and skips the fallback when `>= 2`. Only caller: `newClientInternal`.

### F4 — Push seq prediction (LOW)
Analysis: the vault does **not** become unreadable. The server CAS invariant guarantees a
successful push assigns `lastSeq+1`, exactly the predicted AAD seq. A partial failure (push
received, response lost) is a **lost-update**, not an exploit — recovered by the next pull.
**Recommended (Option A/C):** 409 retry with auto-pull (max 1 retry) + document the CAS invariant.
UX improvement, not security-critical.

## Overlaps with active changes

| Change | Status | Overlap |
|--------|--------|---------|
| `cert-parsing` | Phase 1 done, 2-3 pending | **MEDIUM** — touches `store.go` schema + `Secret` metadata; coordinate schema version bump |
| `otp-support` | complete | minimal |
| `extend-check-password-analysis` | not implemented | none (gui/check/watchtower) |
| `foundation`, `security-audit-fixes` | archived | none |

## Scope ordering

H2 → F1/F2 (PR1, ~380 lines — borderline 400) → F3 → F4 (PR2, low effort). STRICT TDD active —
RED → GREEN → REFACTOR. All new tests are pure-Go (no CGO).

## Risks

1. `cert-parsing` Phase 2-3 schema conflict — coordinate the version bump.
2. Old-client wire compat: a pre-tombstone client ignores `deleted_at` and resurrects the secret
   locally; resolved on upgrade when the tombstone wins by LWW.
3. Purge horizon must run client-side post-merge only, never on the server.
4. F4 retry must cap at 1 to avoid loops.
5. `config_format_version=2` must be written only after BOTH re-wraps succeed.
