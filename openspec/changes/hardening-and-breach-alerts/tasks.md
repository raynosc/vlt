# Tasks: Hardening & Breach Alerts

## Review Workload Forecast

Prod ~950 / incl.tests ~1,800. 400/800-line budgets Exceeded. Delivery: single-pr-default → `size:exception`. Risk: High.

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: stacked-to-main|feature-branch-chain|size-exception|pending
400-line budget risk: High

PR split: PR1 schema+crypto → PR2 runtime+sync → PR3 autolock → PR4 breach. HIBP license must be user-confirmed before PR4.

## Phase 1: Schema v7 + Metadata Encryption [SECURITY]

- [x] 1.1 Add encrypted fields to `secret.go`.
- [x] 1.2 TDD `store_test.go`: v7 on `--fresh`; v6 rejected; grep `vault.sqlite`→no plaintext.
- [x] 1.3 Bump `CurrentSchemaVersion=7`; add `migrations/003_v7_encrypted_metadata.sql`; wire `migrationForVersion`; add `ErrMigrationRequired`.
- [x] 1.4 TDD: encrypt-via-`PackEnvelope` write; HMAC `GetByName`; duplicate→UNIQUE; tampered→integrity.
- [x] 1.5 Drop `Search/ListExpiring/UpdateMetadata/IncrementHOTPCounter` from `Store`; add `Count()`+`ListWithEncryptedAll()`.
- [~] 1.6 Update `watchtower`+`tui` mocks; `go test ./...` green. (watchtower+tui compile; gui/cli pending)

## Phase 2: App Decrypt-Then-Search [SECURITY]

- [ ] 2.1 TDD `gui/app_test.go`: `App.List/Search/GetByName` decrypt in memory; locked→"vault is locked"; zeroize.
- [ ] 2.2 Implement `App.List/Search/GetByName`; move `ListExpiring/UpdateMetadata/IncrementHOTPCounter` to App.
- [ ] 2.3 TDD `tui/{list,search,unlock,add,model}.go`: `m.st`→`*gui.App`; drop direct store calls; `go test ./...` green; TUI e2e.

## Phase 3: Runtime Hardening [SECURITY]

- [ ] 3.1 TDD `store_test.go`: `PRAGMA secure_delete=ON` pre-query; deleted page overwritten.
- [ ] 3.2 TDD: `vault.sqlite/-wal/-shm` 0600; existing 0644 tightened; `chmodVaultFiles`; Windows=no-op.
- [ ] 3.3 TDD `crypto/mlock_test.go` per-OS: darwin mlock; linux mlock+MADV_DONTDUMP; unsupported→no panic.
- [ ] 3.4 `mlock_{darwin,linux,other}.go` via `x/sys/unix`; `LockKey/UnlockKey`; wire into `Engine.DeriveKey`/`VerifyAndDeriveKey`; `Zeroize` after unlock.
- [ ] 3.5 TDD `daemon_test.go`: daemon key mlocked on load; munlock+zeroize on shutdown.

## Phase 4: Sync Conflicts → `sync_conflicts` [SECURITY]

- [ ] 4.1 TDD `sync/client_test.go`: `logConflict` writes `sync_conflicts`; pre-existing `config` `conflict:` keys ignored.
- [ ] 4.2 `logConflict` → INSERT; drop `config` fallback; surface via `cli/sync.go`; `go test ./internal/sync/...` green; `SELECT * FROM sync_conflicts` shows rows.

## Phase 5: GUI Auto-Lock [SECURITY]

- [ ] 5.1 TDD `gui/autolock_test.go`: 5-min idle locks; hide locks; activity resets; 0=disabled; menu shows source.
- [ ] 5.2 `gui/autolock.go` (`AutoLocker{Touch,Tick,Stop,Source}`); wire into GUI: start on unlock; canvas key/mouse + `SetOnVisibilityChanged`/`SetOnFocusLost`.
- [ ] 5.3 Auto-lock menu (1/5/15/30 min, 0=disabled, "use daemon if running"); restart timer on change; `go test ./...` green; manual smoke.

## Phase 6: Breach Corpus + Watchtower [SECURITY]

- [ ] 6.1 TDD `breach/sparse_test.go`: binary search 1k hashes, sparse index, ≤few block reads; `breach/sparse.go`.
- [ ] 6.2 TDD `breach/verify_test.go`: SHA-1 mismatch→discard; SHA-256 mismatch→integrity; `verify.go`+`corpus.go`+bundled SHA-256.
- [ ] 6.3 TDD `cli/breach_test.go`: `vlt breach update` vs stub HTTP; SHA-1 verify; abort on mismatch; `cli/breach.go`+`breach/downloader.go`.
- [ ] 6.4 TDD `watchtower_test.go`: `Analyze` runs `Lookup`; `BreachPasswordFinding`; no-corpus→`BreachCheckSkipped=true`; thread `*breach.Corpus`.
- [ ] 6.5 TDD `cli/check_test.go`: lists breached names; stale>90d warning; "skipped" notice; update `cli/check.go`.
- [ ] 6.6 TDD `gui/watchtower_test.go`: panel renders `BREACHED PASSWORDS`+skip notice; update `gui/watchtower.go`; score/issues; manual clean/breached/no-corpus.

## Phase 7: Verify + Cleanup

- [ ] 7.1 `go test ./...` + `go vet ./...` + `make test`/`make test-cover` green; no coverage drop.
- [ ] 7.2 Manual e2e: `vlt init --fresh`→add secret→`sqlite3 vault.sqlite` (grep=no plaintext)→`vlt check --passwords`→idle→unlock.
- [ ] 7.3 Update `README.md`+`USER_GUIDE.md` (`--fresh`, re-import 1P, breach opt-in, auto-lock).
- [ ] 7.4 Archive change per `sdd-archive` after PR merges.
