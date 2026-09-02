# Proposal: Extend `vlt check` with Password Security Analysis

## Intent

Let `vlt check` optionally analyze password security by reusing the existing GUI Watchtower logic. Today, `vlt check` only validates metadata (duplicate names, expiring certificates). The GUI already decrypts, scores strength, detects reuse, and flags missing 2FA — but that logic is trapped in `internal/gui`. Extracting it enables parity between CLI and GUI without duplication.

## Scope

### In Scope
- Extract `internal/watchtower/` shared package from GUI logic
- Refactor GUI to delegate analysis to `watchtower.Analyze`
- Add `--passwords` flag to `vlt check` (opt-in, requires vault unlock)
- Add CLI integration tests for `--passwords`

### Out of Scope
- JSON output for password analysis
- `store.ListFull()` optimization for bulk decryption
- Making password analysis the default behavior (breaking change)

## Capabilities

### New Capabilities
- `watchtower-analysis`: Shared package for password strength scoring, reuse detection, missing-2FA detection, and certificate expiration counting
- `cli-check`: `vlt check` command behavior, including metadata checks and the new `--passwords` flag

### Modified Capabilities
- None

## Approach

Create `internal/watchtower/` containing `WatchtowerResult`, strength types, `assessPasswordStrength`, and `Analyze(store, engine, key)`. Refactor `gui/app.go:696-824` to call `watchtower.Analyze`. In `cli/check.go`, add `--passwords` bool flag. When true, unlock the vault and run `watchtower.Analyze`, printing findings to stderr. Keep existing metadata checks always enabled. Preserve `crypto.Zeroize` of decrypted buffers in the shared package.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/watchtower/` | New | Shared analysis types and logic |
| `internal/gui/app.go` | Modified | Replace `AnalyzePasswords` body with `watchtower.Analyze` call |
| `internal/cli/check.go` | Modified | Add `--passwords` flag, conditional unlock, result formatting |
| `internal/cli/cli_test.go` | Modified | Add tests for `--passwords` behavior |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| GUI regression | Low | Preserve exact return types and zeroization logic |
| Memory safety (leaked decrypted passwords) | Low | Keep `crypto.Zeroize` in shared code; audit with tests |
| Master password prompt surprise | Low | Update `Long` help text to state vault unlock is required |
| N+1 `GetByName` per password secret | Low | Acceptable for vault-check; vaults are typically <1000 secrets |

## Rollback Plan

Revert the branch. `gui/app.go` can temporarily inline the old logic if `watchtower` needs rework. The `--passwords` flag addition is additive and safe to remove independently.

## Dependencies

- None

## Success Criteria

- [ ] `vlt check --passwords` prompts for unlock and prints weak/reuse/2FA findings
- [ ] `vlt check` without `--passwords` still works passwordlessly
- [ ] GUI Watchtower screen shows identical results as before
- [ ] `watchtower` package has unit tests covering strength, reuse, and 2FA detection
- [ ] Total changed lines stay under 400
