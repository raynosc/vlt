# Apply Progress: hardening-and-breach-alerts

## Status: Partial — Phase 1 core complete; GUI/CLI compilation pending

## Completed Tasks

### Phase 1: Schema v7 + Metadata Encryption [SECURITY]
- [x] 1.1 Add encrypted fields to `secret.go`.
- [x] 1.2 TDD `store_test.go`: v7 on `--fresh`; v6 rejected; grep `vault.sqlite`→no plaintext.
- [x] 1.3 Bump `CurrentSchemaVersion=7`; add `migration007`; wire `migrationForVersion`; add `ErrMigrationRequired`.
- [x] 1.4 TDD: encrypt-via-`PackEnvelope` write; HMAC `GetByName`; duplicate→UNIQUE; tampered→integrity.
- [x] 1.5 Drop `Search/ListExpiring/UpdateMetadata/IncrementHOTPCounter` from `Store`; add `Count()`+`ListWithEncryptedAll()`.
- [~] 1.6 Update `watchtower`+`tui` mocks; `go test ./...` green. (store tests green; watchtower+tui compile; gui/cli still reference old methods)

## TDD Cycle Evidence

| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 1.1 | N/A (structural) | N/A | N/A | N/A | N/A | N/A | N/A |
| 1.2 | `store_v7_test.go` | Integration | N/A (new) | ✅ Written | ✅ Passed | ✅ 4 cases | ✅ Clean |
| 1.3 | `store_v7_test.go` | Integration | N/A (new) | ✅ Written | ✅ Passed | ✅ 2 cases | ✅ Clean |
| 1.4 | `store_v7_test.go` | Integration | N/A (new) | ✅ Written | ✅ Passed | ✅ 3 cases | ✅ Clean |
| 1.5 | `store_v7_test.go` | Integration | N/A (new) | ✅ Written | ✅ Passed | ✅ 2 cases | ✅ Clean |
| crypto.ComputeNameLookup | `namelookup_test.go` | Unit | N/A (new) | ✅ Written | ✅ Passed | ✅ 4 cases | ✅ Clean |

## Test Summary
- **Total tests written**: 15+
- **Total tests passing**: `go test ./internal/store/...` ALL PASS
- **Layers used**: Unit (crypto), Integration (store)
- **Approval tests** (refactoring): None — this was new code

## Files Touched

| File | Action | What Was Done |
|------|--------|---------------|
| `internal/secret/secret.go` | Modified | Added NameLookup, EncryptedName/Notes/Tags/Metadata fields |
| `internal/crypto/namelookup.go` | Created | ComputeNameLookup HMAC-SHA256 helper |
| `internal/crypto/namelookup_test.go` | Created | TDD coverage for HMAC determinism and length |
| `internal/store/store.go` | Modified | v7 schema, new interface, encrypted BLOB I/O, clean-break migration |
| `internal/store/errors.go` | Modified | Added ErrMigrationRequired |
| `internal/store/store_test.go` | Modified | Updated for v7 schema; removed v1-v6 migration tests; updated helpers |
| `internal/store/store_v7_test.go` | Created | TDD tests: fresh v7, v6 rejected, no plaintext, round-trip, duplicate, count, ListWithEncryptedAll |
| `internal/store/store_otp_seed_test.go` | Modified | Updated for v7 encrypted fields |
| `internal/watchtower/watchtower.go` | Modified | Minimal compat: ListWithEncryptedAll, removed GetByName/ListExpiring calls |
| `internal/sync/client.go` | Modified | Added masterKey to Client; updated store calls to use HMAC lookups |
| `internal/daemon/daemon.go` | Modified | Updated GetByName → GetByNameLookup with HMAC |
| `internal/tui/add.go` | Modified | Encrypt metadata before Store; DeleteByLookup with HMAC |
| `internal/tui/list.go` | Modified | GetByNameLookup, SoftDeleteByLookup, ListExpiring stubbed |
| `internal/tui/unlock.go` | Modified | ListExpiring stubbed |
| `internal/tui/tui_test.go` | Modified | Updated mockStore for new Store interface |

## Deviations from Design
- `migrations/003_v7_encrypted_metadata.sql` task name was aspirational; actual implementation uses embedded constant `migration007` following the existing Go constant pattern (no SQL files exist in the repo).
- Old store methods (Search, ListExpiring, UpdateMetadata, IncrementHOTPCounter) removed from the `Store` interface but not yet migrated to the App layer. GUI and CLI packages still call the old `*store.SQLStore` methods and need updating in the next batch.
- HIBP license note: the design incorrectly cites "CC BY 4.0" for HIBP; no HIBP-related code was written in this batch. The license correction is deferred to Phase 6.

## Issues Found
- `go build ./...` still fails in `internal/gui/app.go` and `internal/cli/*.go` because they reference removed store methods (Search, GetByName, Delete, SoftDelete, ListExpiring, UpdateOTPSeedAndMetadata with old signature).
- Resolution: next batch will update `gui/app.go` to decrypt metadata in-memory (Phase 2.2) and update CLI callers to use HMAC lookups or migrate to App layer.

## Remaining Tasks

### Phase 1 (completion)
- [ ] 1.6 Finish updating `gui/app.go` and `cli/*.go` to compile and pass tests.

### Phase 2: App Decrypt-Then-Search [SECURITY]
- [ ] 2.1 TDD `gui/app_test.go`: `App.List/Search/GetByName` decrypt in memory; locked→"vault is locked"; zeroize.
- [ ] 2.2 Implement `App.List/Search/GetByName`; move `ListExpiring/UpdateMetadata/IncrementHOTPCounter` to App.
- [ ] 2.3 TDD `tui/{list,search,unlock,add,model}.go`: `m.st`→`*gui.App`; drop direct store calls; `go test ./...` green; TUI e2e.

### Phase 3-7
See tasks.md for full list (Phases 3–7 untouched).

## Commit Hashes
- `1fe523a` feat(store): schema v7 clean break with encrypted metadata and HMAC name lookup

## Workload / PR Boundary
- Mode: size:exception (single PR, maintainer-approved)
- Current work unit: Phase 1 foundation (schema v7 + store layer)
- Boundary: commits up to `1fe523a`
- Estimated review budget impact: ~600 lines (store layer + tests), within the 800-line exception budget for the full change
