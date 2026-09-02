# Archive Report: Sync Trust Model v2

**Change**: sync-trust-model-v2  
**Archived**: 2026-06-02  
**Status**: Complete and merged to main  
**Project**: passwd  
**Artifact Store Mode**: hybrid (openspec + engram)

---

## Executive Summary

The sync-trust-model-v2 change successfully closed all remaining E2E-sync trust-model gaps from the security audit. Two chained PRs landed on main: PR #7 (H2 tombstones + F1/F2 anti-rollback anchor) and PR #8 (F3 config_format_version nil-AAD gate + F4 push 409 retry). All 200 tasks across 4 feature groups completed, schema transitioned to v6, and verification passed.

---

## What Shipped

### H2 — Tombstones
- Added `DeletedAt *time.Time` (json omitempty) to `secret.Secret`
- Schema v6: added `deleted_at` nullable column (DEFAULT NULL)
- Implemented `store.SoftDelete(name)`, `ListWithTombstones()`, `PurgeTombstones(before)`
- Updated merge to use `effectiveTS`-based LWW; tombstones win over stale live records
- Client-side post-merge purge (30-day horizon); prevents server-side purge
- Deleted secrets survive sync without resurrection risk from malicious server replay
- All call sites audited per ADR-5 (user deletion → `SoftDelete`; internal replace → hard `Delete`)

### F1/F2 — Fresh-Device Anti-Rollback Anchor
- Added `VaultSeq int64` to `RegisterResponse` (echoed at registration time)
- Client persists `registration_seq` from `VaultSeq` on first registration
- Pull enforces: `pullResp.Seq >= max(lastSeq, registrationSeq)` (rejects stale blobs)
- Brand-new vaults (seq=0): pre-flight single `GET /status` anchors the floor before first pull (prevents race-condition stale blob)
- Protects fresh devices from compromised server replay attacks

### F3 — Config Format Version Gate (nil-AAD Prohibition)
- Added `configFormatVersion` parameter to `UnwrapConfigValue()`
- Constants: `ConfigFormatVersionLegacy=1`, `ConfigFormatVersionAAD=2`
- Version=2 written ONLY after BOTH `api_key` and `sync_encryption_key` re-wrap succeed (atomic invariant)
- When version >= 2: skips nil-AAD fallback, enforces AAD-encrypted decryption only
- Legacy vaults (version < 2): may still use nil-AAD fallback during migration only
- Prevents silent downgrade of key-name binding on already-migrated vaults
- **Known Limitation**: TOFU (Trust-On-First-Use) on fresh devices adopting existing vaults relies on pre-flight seq anchor (F1/F2), not config version. If a fresh device's first pull is compromised before config_format_version=2 is written, the nil-AAD gate cannot prevent fallback. Mitigation: F1/F2 pre-flight anchoring prevents this vector by rejecting stale blobs before they reach `mergeSecrets`.

### F4 — Push 409 Auto-Pull Retry
- Extracted `Push` logic into `pushOnce()` (returns `errSeqConflict` on HTTP 409)
- `Push` now: try once → on 409 conflict → auto-pull + retry once
- Second 409 surfaces error (no further retry, no loop)
- Vault remains readable throughout (no partial state)
- Fixes lost-update UX issue (not a security exploit; CAS invariant guarantees vault consistency)

---

## Schema and Wire Protocol Changes

### Schema Version
- **Current**: v6 (was v5)
- **Artifact**: `internal/store/store.go:CurrentSchemaVersion = 6`
- **Migration**: `ALTER TABLE secrets ADD COLUMN deleted_at TEXT DEFAULT NULL` (additive, non-destructive)
- **Backward Compat**: v5 code reads v6 schema safely (ignores `deleted_at` column); rollback safe

### Wire Protocol
- `RegisterResponse`: added `vault_seq` field (0 for new vault, current seq for existing)
- `SyncPayload`: no version field added (backward-compatible; old clients ignore `deleted_at` via omitempty)
- Config keys: `registration_seq` (new), `config_format_version` (new, defaults to 1 if absent)

---

## Merged PRs

| PR | Title | Features | Lines Changed |
|----|-------|----------|--------|
| #7 | H2 tombstones + F1/F2 anti-rollback anchor | H2, F1, F2 | ~380 |
| #8 | F3 config_format_version nil-AAD gate + F4 push 409 retry | F3, F4 | ~120 |

Both merged to main. All integration tests pass.

---

## Merged Delta Specs

Delta specs were merged into main specs under `openspec/specs/`:

| Domain | File | Changes |
|--------|------|---------|
| sync-client | `openspec/specs/sync-client/spec.md` | MODIFIED: LWW Merge with Conflict Log (tombstone semantics); ADDED: Fresh-Device Anti-Rollback, Brand-New Vault Pre-Flight, Push 409 Auto-Pull Retry |
| sync-security | `openspec/specs/sync-security/spec.md` | ADDED: Config Format Version Gate (nil-AAD prohibition) |
| cli-store-robustness | `openspec/specs/cli-store-robustness/spec.md` | ADDED: Schema v6 with Soft-Delete Support |
| sync-server | `openspec/specs/sync-server/spec.md` | MODIFIED: Vault Registration (vault_seq in response) |

---

## Artifacts Archived

- `proposal.md` ✅ — Change intent, scope, approach, risk assessment
- `exploration.md` ✅ — Pre-design findings per H2/F1/F2/F3/F4
- `design.md` ✅ — Architecture decisions (ADRs), detailed per-item design
- `tasks.md` ✅ — 200+ tasks across 4 feature groups; all [x] marked complete
- `specs/sync-client/spec.md` ✅ — Delta spec (merged to main)
- `specs/sync-security/spec.md` ✅ — Delta spec (merged to main)
- `specs/cli-store-robustness/spec.md` ✅ — Delta spec (merged to main)
- `specs/sync-server/spec.md` ✅ — Delta spec (merged to main)

Archive folder: `openspec/changes/archive/2026-06-02-sync-trust-model-v2/`

---

## Test Results

- **STRICT TDD**: all tests written RED first, then GREEN, then REFACTOR
- **Test framework**: pure-Go (modernc.org/sqlite, net/http/httptest); no CGO
- **Coverage**: Schema canary tests (`store_otp_seed_test.go` verifies v6 migration); client merge tests; server integration tests
- **Final gate**: `go test ./...` all green from repo root
- **Build**: `go build ./...` no compile errors; `Store` interface fully satisfied

---

## Known Limitations

### TOFU Anti-Rollback on Fresh Devices (F1/F2 Prerequisite)
- **Scenario**: A fresh device adopting an existing vault without a local history to compare against.
- **Threat**: Compromised server replays a stale blob.
- **Mitigation**: F1/F2 pre-flight seq anchoring (`GET /status` on first pull) establishes the minimum seq floor. This prevents the stale blob from being accepted, ensuring `mergeSecrets` never processes a pre-rollback state.
- **Why F3 alone is insufficient**: `config_format_version=2` (F3) is only written AFTER both crypto re-wraps succeed (line ~54 of `client.go`). If the first pull arrives before re-wrapping, the vault is still at version < 2 and can fall back to nil-AAD. F1/F2 blocks this by rejecting the stale pull at the seq check, before `mergeSecrets` runs.
- **No fix required**: F1/F2 is the architectural solution for this threat. F3 hardens an already-migrated vault (version >= 2) to prevent downgrade. Together, they protect both fresh and migrated devices.

---

## Rollback Plan

All changes are reversible:

1. **Schema rollback**: revert to v5 code; v6 `deleted_at` column harmlessly ignored
2. **Config keys**: `registration_seq` and `config_format_version` dropped; fall back to pre-v2 behavior
3. **Client logic**: revert `Pull` seq check and `Push` retry loop; restore original LWW (no tombstones)
4. **Server**: revert `RegisterResponse.VaultSeq` echo (no state change needed)

Each PR can be reverted independently without data corruption.

---

## Sign-Off Checklist

- [x] Proposal reviewed and accepted
- [x] Spec deltas merged into main specs
- [x] Design completed (4 ADRs documented)
- [x] Tasks completed (all 200+ marked [x])
- [x] RED tests written first; all failing
- [x] GREEN implementation complete; all tests pass
- [x] REFACTOR cleanup done; code review passed
- [x] PR #7 merged to main (H2 + F1/F2)
- [x] PR #8 merged to main (F3 + F4)
- [x] Integration tests green (`go test ./...`)
- [x] Build clean (`go build ./...`)
- [x] Schema v6 confirmed in code and applied
- [x] Delta specs merged into `openspec/specs/`
- [x] Archive folder created and change moved

---

## SDD Cycle Complete

The sync-trust-model-v2 change is now fully planned, implemented, verified, and archived. Ready for the next SDD change.
