# Proposal: Security Audit Fixes (Critical + High)

## Intent

Fix 13 CRITICAL and HIGH severity findings from a comprehensive security review of the passwd/vlt Go codebase. MEDIUM/LOW findings are deferred to a follow-up change. This is a security-hardening patch with no new features.

## Scope

### In Scope
- **CRITICAL (4)**: sync-server auth bypass, macOS peer auth fail-open, double-close panic, zombie/goroutine leak
- **HIGH (9)**: default bind 0.0.0.0, unauthenticated registration DoS, world-readable DB, ineffective TUI zeroization, TOTP goroutine leak, HOTP counter race, panic in recovery encoding, duplicated colors and password charset

### Out of Scope
- MEDIUM/LOW findings (~100 remaining)
- Feature additions or UI redesigns

## Capabilities

### New Capabilities
- None

### Modified Capabilities
- `sync-server`: vault UUID authz, localhost default, per-IP rate limit, DB `0o600`
- `tui-browser`: `[]byte` plaintext, deduplicate colors/charset
- `gui`: cancellable context for TOTP goroutines

## Approach

Apply the targeted per-finding fixes identified by the audit:

- **Auth & hardening**: vault UUID authz; macOS fail-closed; localhost default; rate-limit register; DB `0o600`
- **Stability & leaks**: `sync.Once` guard; `cmd.Wait()`; cancellable TOTP goroutines; atomic HOTP counter
- **Memory safety**: TUI plaintext as `[]byte`; error on invalid recovery key length
- **Deduplication**: shared colors to `internal/theme/colors.go`; charset to `internal/crypto/charset.go`

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `syncserver/` | Modified | Authz, rate limit, localhost default, DB `0o600` |
| `daemon/` | Modified | Fail-closed peer auth, `sync.Once` guard |
| `cmd/vlt-quick/` | Modified | Zombie prevention |
| `tui/` | Modified | `[]byte` plaintext, dedup colors/charset |
| `gui/` | Modified | Cancellable goroutines, dedup colors |
| `cli/totp.go` | Modified | Atomic HOTP counter |
| `crypto/recovery.go` | Modified | Error instead of panic |
| `internal/theme/` | New | Shared colors |
| `internal/crypto/` | New | Shared charset |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Rate limiting breaks CI registration | Low | Generous per-IP defaults; configurable threshold |
| `[]byte` plaintext causes TUI regressions | Low | Full test suite before commit |
| `localhost` default breaks remote deploy | Low | Remote deploys already override address |

## Rollback Plan

Revert the single commit. All changes are backward-compatible fixes with no schema changes. The registration rate limit is additive and safe to remove.

## Dependencies

- None

## Success Criteria

- [ ] `go test ./...` passes with 0 regressions
- [ ] `golangci-lint` reports 0 warnings
- [ ] All 13 findings verified fixed
- [ ] No new MEDIUM/LOW findings introduced
