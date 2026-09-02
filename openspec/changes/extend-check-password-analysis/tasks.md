# Tasks: Extend `vlt check` with Password Security Analysis

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~750–850 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 → PR 2 |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Extract `internal/watchtower/` and unit tests | PR 1 | Base: main |
| 2 | Wire GUI and CLI with integration tests | PR 2 | Base: main (after PR 1) |

## Phase 1: Foundation

- [ ] 1.1 Create `internal/watchtower/watchtower.go` with types, `AssessPasswordStrength`, `Analyze`, and `sha256Sum` moved from `gui/app.go`
- [ ] 1.2 Retain `PasswordStrength.String()` and `ColorHex()` methods for GUI compatibility
- [ ] 1.3 Zeroize decrypted buffers inside `watchtower.Analyze` via `crypto.Zeroize` before returning

## Phase 2: Core Logic Tests

- [ ] 2.1 Write `internal/watchtower/watchtower_test.go`: table-driven `AssessPasswordStrength` tests (empty, common, short, fair, strong, very strong)
- [ ] 2.2 Add reuse detection tests: 0 duplicates, 1 unique, 2+ shared passwords
- [ ] 2.3 Add missing-2FA tests: with OTPAuth, without OTPAuth, missing URL
- [ ] 2.4 Add zeroization audit test asserting `crypto.Zeroize` is called on decrypted buffers

## Phase 3: GUI Refactor

- [ ] 3.1 Modify `internal/gui/app.go`: remove private types, `assessPasswordStrength`, `sha256Sum`, and old `AnalyzePasswords` body
- [ ] 3.2 Delegate `AnalyzePasswords` to `watchtower.Analyze(a.store, a.engine, a.key)`
- [ ] 3.3 Verify GUI compiles and `PasswordStrengthColor`/`PasswordStrengthLabel` map to `watchtower` methods

## Phase 4: CLI Integration

- [ ] 4.1 Modify `internal/cli/check.go`: add `--passwords` flag with help text stating vault unlock is required
- [ ] 4.2 If `--passwords`, call `unlockVault(vaultPath)` then `watchtower.Analyze(s, engine, key)` after metadata checks
- [ ] 4.3 Print weak/reuse/2FA findings to stderr and aggregate counts into `issuesFound`
- [ ] 4.4 Preserve exit 0 only when total issues (metadata + password) equals zero

## Phase 5: Integration & Regression Testing

- [ ] 5.1 Extend `internal/cli/cli_test.go`: test `vlt check --passwords` on locked vault prompts and prints findings
- [ ] 5.2 Test `vlt check --passwords` with no password secrets produces no password section
- [ ] 5.3 Test `vlt check` without `--passwords` on locked vault passes without prompt
- [ ] 5.4 Ensure existing `TestCheck_*` assertions continue to pass
