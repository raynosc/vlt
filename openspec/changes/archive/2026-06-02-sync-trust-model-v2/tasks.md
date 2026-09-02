# Tasks: Sync Trust Model v2

> STRICT TDD active (`go test ./...`). Every slice follows RED → GREEN → REFACTOR.
> All tests pure-Go (modernc.org/sqlite, net/http/httptest). No CGO.

---

## PREREQUISITE (BLOCKING — must resolve before any implementation task)

- [x] **P.0** — Confirm cert-parsing Phase 2-3 schema state against `internal/store/store.go:CurrentSchemaVersion`.
  Current observed value: **v5** (as of 2026-06-02). cert-parsing has NOT yet bumped the schema.
  **Decision pinned: this change claims v6 = `deleted_at`.** Schema version used: **v6**. 
  If cert-parsing merges a v6 before this lands → rebase to v7 (change constant + case; SQL is version-agnostic).

---

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~420–500 (additions + deletions) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1 = H2 + F1/F2 → PR2 = F3 + F4 |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending (decision needed before apply) |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Tombstones (H2) + Anti-rollback anchor (F1/F2) | PR 1 | Base: main; schema v6 + merge/purge + registration_seq; self-contained rollback |
| 2 | Config format version gate (F3) + Push retry (F4) | PR 2 | Base: PR 1 branch; depends on Store interface stable from PR1 |

---

## Group H2 — Tombstones

> RED tests mapped from Design §4 "H2 Tombstones" + specs/cli-store-robustness/spec.md

### H2-R: Write failing tests first (RED phase)

- [x] **H2.1-RED** — `internal/store/store_test.go`: add table-driven tests for `SoftDelete`:
  sets `deleted_at`; row persists; `List`/`GetByName`/`Search`/`GetByID`/`ListExpiring` exclude it;
  `ListWithTombstones` includes it; `SoftDelete` on missing name → `ErrNotFound`; on already-deleted → `ErrNotFound`.
  `PurgeTombstones(before)` deletes only rows with `deleted_at < before` and returns count; a row with
  `deleted_at = now-29d` survives. Run `go test ./internal/store/...` — all new tests FAIL (RED).

- [x] **H2.2-RED** — `internal/sync/client_test.go`: add table-driven tests for `mergeSecrets` (effectiveTS LWW):
  (a) remote tombstone `DeletedAt=100 > local UpdatedAt=80` → winner is tombstone; (b) anti-resurrection:
  replayed pre-delete remote `UpdatedAt=50 < local tombstone `DeletedAt=100` → local tombstone wins;
  (c) tie `effectiveTS` equal: tombstone beats live; both-tombstone → local wins; (d) tombstone only
  remotely, no local row → inserted as tombstone. Run — FAIL (RED).

- [x] **H2.3-RED** — `internal/sync/client_test.go`: add purge integration tests: `Pull` purges tombstones
  older than 30d post-merge; a 29d tombstone survives; `Push` never triggers purge. Run — FAIL (RED).

- [x] **H2.4-RED** — Old-client compat test (no separate file, append to `client_test.go`): marshal
  a `secret.Secret` WITH `DeletedAt` set → JSON must NOT contain `"deleted_at"` when nil; marshal with
  `DeletedAt != nil` → key present; unmarshal a payload containing `"deleted_at"` into a struct without
  the field (raw map round-trip) → no error. Run — FAIL (RED).

### H2-G: Implement (GREEN phase)

- [x] **H2.5** — `internal/secret/secret.go`: add `DeletedAt *time.Time \`json:"deleted_at,omitempty"\`` to `Secret` struct.

- [x] **H2.6** — `internal/store/store.go`: bump `CurrentSchemaVersion = 6`; add `migration006` constant
  (`ALTER TABLE secrets ADD COLUMN deleted_at TEXT DEFAULT NULL`); add `case 6:` to `migrationForVersion`.

- [x] **H2.7** — `internal/store/store.go`: add `SoftDelete(name string) error`, `ListWithTombstones() ([]secret.Secret, error)`,
  and `PurgeTombstones(before time.Time) (int, error)` to the `Store` interface.

- [x] **H2.8** — `internal/store/store.go` (`SQLStore`): implement `SoftDelete` — `UPDATE secrets SET deleted_at=?, updated_at=? WHERE name=? AND deleted_at IS NULL`; returns `ErrNotFound` if 0 rows affected.

- [x] **H2.9** — `internal/store/store.go` (`SQLStore`): implement `ListWithTombstones` — same as `List` without `WHERE deleted_at IS NULL` filter; returns full `encrypted_value`.

- [x] **H2.10** — `internal/store/store.go` (`SQLStore`): implement `PurgeTombstones(before time.Time) (int, error)` — `DELETE FROM secrets WHERE deleted_at IS NOT NULL AND deleted_at < ?` with RFC3339 formatted `before`.

- [x] **H2.11** — `internal/store/store.go`: update `getBy`/`scanMetadata` to scan `deleted_at` as `sql.NullString` → parse RFC3339 → set `sec.DeletedAt`. Add `WHERE deleted_at IS NULL` to `List`, `Search`, `GetByName`, `GetByID`, `ListExpiring`.

- [x] **H2.12** — `internal/sync/client.go`: add `effectiveTS(s secret.Secret) time.Time` helper (ADR-2). Add `isTomb(s secret.Secret) bool` helper. Update `mergeSecrets` to use `effectiveTS`-based winner predicate (ADR-2 remoteWins formula). Pull apply-loop: branch on `winner.DeletedAt` — tombstone+live-local → `SoftDelete`; tombstone+no-local → `Store` with `DeletedAt` set; live+newer → existing hard-Delete then Store path (unchanged).

- [x] **H2.13** — `internal/sync/client.go`: add `tombstonePurgeHorizon = 30 * 24 * time.Hour` constant and `purgeExpiredTombstones() error` method. Call at end of `Pull()` after `last_sync_seq` saved.

- [x] **H2.14** — `internal/sync/client.go` `Push`: change `List()` to `ListWithTombstones()` so tombstones propagate (ADR-7).

### H2-A: ADR-5 call-site audit (per-site, non-blanket)

Following the ADR-5 table exactly — do NOT bulk rename:

- [x] **H2.15** — `internal/cli/rm.go:66`: change `s.Delete(name)` → `s.SoftDelete(name)` (genuine user deletion).

- [x] **H2.16** — `internal/gui/app.go:369`: kept as hard Delete — this is a replace/re-store flow (`Delete and re-store` comment). Added `// hard Delete: internal replace, not user deletion` comment per ADR-5.

- [x] **H2.17** — `internal/gui/app.go:425`: kept as hard Delete — re-insert for OTP seed add. Added `// hard Delete: internal replace, not user deletion` comment per ADR-5.

- [x] **H2.18** — `internal/gui/app.go:478` (`DeleteSecret` method): changed `store.Delete` → `store.SoftDelete` (genuine user deletion via GUI). ✓

- [x] **H2.19** — `internal/gui/app.go:902`: **FINDING: this is an import-overwrite (replace) path**, not a genuine user deletion. Code is `if !overwrite { skip } else { st.Delete(rec.Title) }` — the `else` branch runs when the import flag `overwrite=true`, replacing existing entries. ADR-5 explicitly lists `cli/import.go` overwrite paths as hard Delete. Added `// hard Delete: internal replace, not user deletion` comment. **Kept as hard Delete.**

- [x] **H2.20** — `internal/gui/gui.go:1813`: this site is a metadata-update replace pattern (`GetByName → update metadata → Delete → Store`). Kept as hard Delete, added `// hard Delete: internal replace, not user deletion` comment.

- [x] **H2.21** — `internal/tui/list.go:446`: change `m.st.Delete(sec.Name)` → `m.st.SoftDelete(sec.Name)` (genuine user deletion from TUI list). ✓

- [x] **H2.22** — `internal/cli/add.go:107,244`, `internal/cli/edit.go:144`, `internal/cli/import.go:156,398`, `internal/tui/add.go:216`, `internal/sync/client.go` (apply loop): **NO CHANGE** — these are replace/internal flows per ADR-5. Added inline comment `// hard Delete: internal replace, not user deletion` to each site.

### H2-REFACTOR

- [x] **H2.23** — Run `go test ./...` all green. Remove any dead branches revealed by the predicate change. Verify `store_test.go` schema-version canary still passes (it checks `CurrentSchemaVersion == applied migrations`).

---

## Group F1/F2 — Registration Seq Anti-Rollback Anchor

> RED tests mapped from Design §4 "F1/F2 registration_seq" + specs/sync-server/spec.md + specs/sync-client/spec.md

### F1/F2-R: Write failing tests first (RED phase)

- [x] **F1.1-RED** — `internal/syncserver/handler_test.go`: register new vault → `RegisterResponse.VaultSeq == 0`; register/adopt existing vault at seq N → `VaultSeq == N`. Run — FAIL (RED).

- [x] **F1.2-RED** — `internal/sync/client_test.go` (httptest): `Pull` with `registration_seq=5`, server serves seq 3 → rollback error; `registration_seq=5`, `lastSeq=50`, server serves seq 50 → accepted (max rule). Fresh vault `effectiveSeq=0`: pre-flight `GET /status` returns seq 4, then `/pull` returns seq 2 → rejected; count `/status` hits == 1 (no loop). `registration_seq=0`, `lastSeq=7`, server seq 7 → accepted (regression guard: no error on equal seq). Run — FAIL (RED).

### F1/F2-G: Implement (GREEN phase)

- [x] **F1.3** — `internal/sync/types.go` (or wherever `RegisterResponse` is defined): add `VaultSeq int64 \`json:"vault_seq"\``.

- [x] **F1.4** — `internal/syncserver/handler.go` `handleRegister`: after `CreateVault`/vault-lookup, read current seq via `GetVaultStatus` and set `resp.VaultSeq`. New vault → 0; existing → current seq.

- [x] **F1.5** — `internal/cli/sync.go` (sync init flow): after successful registration, write `registration_seq` config key from `RegisterResponse.VaultSeq` (string-encoded int64, same convention as `last_sync_seq`).

- [x] **F1.6** — `internal/sync/client.go` `Pull`: read `registration_seq` (0 if absent); compute `effectiveSeq = max(lastSeq, registrationSeq)`; reject if `pullResp.Seq < effectiveSeq` with rollback error. Pre-flight: if `effectiveSeq == 0`, issue single `GET /status`, persist `registration_seq = statusSeq` BEFORE decrypting; then require `pullResp.Seq >= statusSeq`. Guard with `if effectiveSeq == 0` — no loop, no retry.

### F1/F2-REFACTOR

- [x] **F1.7** — Run `go test ./...` all green. Confirmed `/status` hit count == 1 in pre-flight test (TestPull_FreshVault_PreflightRunsOnce passes).

---

## Group F3 — Config Format Version Gate

> RED tests mapped from Design §4 "F3 config_format_version" + specs/sync-security/spec.md

### F3-R: Write failing tests first (RED phase)

- [x] **F3.1-RED** — `internal/sync/secrets_test.go`: `UnwrapConfigValue(..., configVersion=2)` on a nil-AAD legacy blob → returns auth error, no plaintext. `UnwrapConfigValue(..., configVersion=1)` on same blob → fallback succeeds, `wrapped=false`. Run — FAIL (RED). (Existing 5 call sites in this file will also fail compilation — fix all 5 to pass explicit `1` as part of this RED task so the file compiles; those 5 are not behavior changes.)

- [x] **F3.2-RED** — `internal/sync/client_test.go`: after `newClientInternal` lazy re-wraps both values successfully, `config_format_version` config key reads `"2"`. Inject forced `ConfigSet` failure on one re-wrap → version stays `"1"`. Run — FAIL (RED).

### F3-G: Implement (GREEN phase)

- [x] **F3.3** — `internal/sync/secrets.go`: add `configVersion int` parameter to `UnwrapConfigValue`. When `configVersion >= 2`, skip nil-AAD fallback block (lines 58-63); return AAD-decrypt error directly. Add package-level constants: `ConfigFormatVersionLegacy = 1`, `ConfigFormatVersionAAD = 2`.

- [x] **F3.4** — Update all 7 `UnwrapConfigValue` call sites (2 prod + 5 tests):
  - `internal/sync/client.go:45,54` (`newClientInternal`): read `config_format_version` once → pass to both calls.
  - `internal/cli/sync.go:400` (`runSyncShowAPIKey`): read key → pass.
  - `internal/sync/secrets_test.go` (5 existing call sites): pass explicit `1` (preserve legacy-fallback assertions).

- [x] **F3.5** — `internal/sync/client.go` `newClientInternal`: capture `ConfigSet` error for both re-wrap blocks. Gate `config_format_version = 2` write on `apiOK && syncOK` (ADR-9 atomic invariant). Use `_ =` pattern only for the version write itself, not the re-wrap errors.

- [x] **F3.6** — `internal/cli/sync.go` (sync init): write `config_format_version = 2` after fresh vault initialization (born in new format per ADR-9).

### F3-REFACTOR

- [x] **F3.7** — Run `go test ./...` all green. Verify existing `secrets_test.go` legacy-fallback tests still pass with explicit `configVersion=1`.

---

## Group F4 — Push 409 Auto-Pull Retry

> RED tests mapped from Design §4 "F4 409 retry" + specs/sync-client/spec.md

### F4-R: Write failing tests first (RED phase)

- [x] **F4.1-RED** — `internal/sync/client_test.go` (httptest): (a) server returns 409 once then 200 → `Push` succeeds; assert `/pull` hit == 1, `/push` hit == 2; (b) server returns 409 twice → `Push` returns "after auto-pull retry" error; assert `/push` hit == 2 (no third push); (c) `errSeqConflict` sentinel is not exported (verify it's unexported). Run — FAIL (RED).

### F4-G: Implement (GREEN phase)

- [x] **F4.2** — `internal/sync/client.go`: add unexported `var errSeqConflict = errors.New("sequence conflict")`.

- [x] **F4.3** — `internal/sync/client.go`: extract current `Push` body into `pushOnce() (int64, error)`; return `errSeqConflict` on HTTP 409.

- [x] **F4.4** — `internal/sync/client.go`: rewrite `Push` to call `pushOnce()`; on `errSeqConflict` → call `Pull()` once → call `pushOnce()` once; on second `errSeqConflict` → return "sequence conflict after auto-pull retry" error (no further retry, no loop). Non-conflict errors pass through directly.

### F4-REFACTOR

- [x] **F4.5** — Run `go test ./...` all green. Verify no `for` loop in new `Push`. Confirm vault readable on error path (no partial state left).

---

## Final Integration Gate

- [x] **INT.1** — Run full suite `go test ./...` from repo root. All tests green.
- [x] **INT.2** — Build binary `go build ./...` — no compile errors. Confirm `Store` interface is satisfied: `SQLStore` implements `SoftDelete`, `ListWithTombstones`, `PurgeTombstones`, `UpdateTombstoneDeletedAt`.
- [x] **INT.3** — Confirm `internal/store/store_otp_seed_test.go` schema-version canary passes with `CurrentSchemaVersion = 6`.
