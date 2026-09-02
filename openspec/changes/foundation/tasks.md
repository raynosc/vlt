# Tasks: Foundation

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Total files | ~30 |
| Total estimated lines | ~1,500 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | 4 chained PRs (feature-branch-chain) |
| Delivery strategy | auto-chain |
| Chain strategy | feature-branch-chain |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High

### Proposed PR Slices (feature-branch-chain)

Tracker branch accumulates all layers. Each child PR targets the previous PR branch. Only tracker merges to main.

1. **PR #1 (tracker→main)**: Project scaffolding + Crypto engine — ~400 lines, 10 files
2. **PR #2 (child→PR#1)**: Vault config + Secret storage — ~350 lines, 6 files
3. **PR #3 (child→PR#2)**: CLI commands + main entry — ~420 lines, 8 files
4. **PR #4 (child→PR#3)**: TUI browser — ~350 lines, 7 files

---

## Phase 1: Infrastructure + Crypto (PR #1)

### Task 0: Project scaffolding
- **Capability**: infrastructure
- **Depends on**: none
- **Files**: go.mod, .gitignore, .golangci.yml, Makefile
- **Estimate**: 4 files, ~50 lines
- **Verification**: `go build ./...` succeeds; `go vet ./...` passes; `golangci-lint run` passes
- [x] Implemented — 14 files, ~93 lines configuration, all verifications pass

### Task 1: Crypto engine — DeriveKey, Encrypt/Decrypt envelope, VerifyMasterKey, recovery kit, Zeroize
- **Capability**: crypto-engine
- **Depends on**: Task 0 ✅
- **Files**: internal/crypto/engine.go, zeroize.go, verify.go, recovery.go, wordlist.go, engine_test.go
- **Estimate**: 6 files, ~350 lines
- **Verification**: `go test ./internal/crypto/...` — KDF deterministic, encrypt/decrypt round-trip, wrong key/tampered ciphertext rejected, recovery kit round-trip, bad mnemonic fails
- [x] Implemented — 6 files, ~780 lines, 22/22 tests pass

---

## Phase 2: Secret Storage (PR #2)

### Task 2: Vault path + SQLite store — config path, Store interface + SQLStore, migrations, CRUD
- **Capability**: secret-storage
- **Depends on**: Task 1
- **Files**: internal/config/config.go, internal/config/config_test.go, internal/secret/secret.go, internal/store/errors.go, store.go, migrations/001_initial.sql, store_test.go
- **Estimate**: 6 files, ~350 lines → 7 files, ~1,350 lines
- **Verification**: `go test ./internal/store/...` — Init creates schema, Store/Get round-trip, duplicate/not-found errors, List metadata-only, Search filters by name/tag, empty vault returns empty
- [x] Implemented — 7 files, ~1,350 lines, 16/16 store tests pass + 6/6 config tests pass, 0 lint issues

---

## Phase 3: CLI (PR #3)

### Task 3: CLI subcommands (init, add, get, list, rm) + cmd/passwd/main.go dispatching to CLI
- **Capability**: cli-commands
- **Depends on**: Task 2 ✅
- **Files**: internal/cli/root.go, init.go, add.go, get.go, list.go, rm.go, search.go, cli_test.go, cmd/passwd/main.go, internal/store/store.go (+ConfigGet/Set)
- **Estimate**: 8 files, ~420 lines
- **Verification**: `go test ./internal/cli/...` — table-driven tests for each subcommand (flag parsing, output format, error messages); init creates vault + stores verify hash; add encrypts + stores; get decrypts + prints; list shows metadata; rm deletes with/without --force; --json produces valid JSON
- [x] Implemented — 10 files, ~940 lines, 11/11 CLI tests pass + 19/19 store tests pass

---

## Phase 4: TUI (PR #4)

### Task 4: Bubble Tea TUI — unlock screen, scrollable list, detail view with decryption, search overlay, quit
- **Capability**: tui-browser
- **Depends on**: Task 3 ✅
- **Files**: internal/tui/model.go, unlock.go, list.go, detail.go, search.go, tui_test.go; cmd/passwd-tui/main.go (separate entrypoint)
- **Estimate**: 7 files, ~350 lines → 7 files, ~1,642 lines (with tests)
- **Verification**: `go test ./internal/tui/...` — all 20 tests pass (unlock correct/wrong/empty/max-attempts/Ctrl+C, list display/navigation/empty, detail reveal-toggle/Esc-back, search filter/Esc-clear/navigation, quit key-zeroization, unpack-envelope, run-filter)
- [x] Implemented — 7 files, ~1,642 lines, 20/20 tests pass
