# Proposal: Audit Fixes Phase 2

## Intent

Fix ~20 MEDIUM-impact security and data-integrity findings. Focus: crypto fidelity, daemon resilience, sync transport security, CLI robustness.

## Scope

### In Scope
- Crypto: read stored Argon2 params; fix OTP escaping, silent parse errors, manual URI construction
- Daemon: panic recovery, 300s lockout, `[]byte` password zeroization, TOCTOU guard
- Sync: HTTPS enforcement, masked API key, `show-key`
- Linux keychain: encrypted D-Bus session
- CLI: persistent rate-limit file, fix shadowing, log keychain errors, recovery-kit path guard
- Unified version, exit codes, syncserver route constants

### Out of Scope
- ~80 LOW/cosmetic findings; new features

## Capabilities

### New
- `internal/version`: shared version constant
- `internal/cli/exitcodes`: shared exit codes

### Modified
- `cli-crypto`: read stored Argon2 params; fallback to defaults
- `tui-browser`: OTP URI via `url.URL`/`url.Values`; label uses `PathUnescape`
- `daemon`: `recover()` in handler; 300s progressive lockout; `Request.Password` as `[]byte`; socket TOCTOU fix
- `sync-client`: reject `http://` without `--insecure`; mask API key
- `sync-server`: route/env constants

## Approach

Localized security patches with regression tests. Strict TDD. Single PR with `size:exception`.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `crypto/engine.go` | Modified | Stored `Argon2Params` |
| `cli/init.go`, `root.go`, `daemon.go`, `gui/app.go` | Modified | Pass stored params to `NewEngine` |
| `otp/uri.go` | Modified | `PathUnescape` |
| `store/store.go` | Modified | Return `time.Parse` errors |
| `gui/gui.go` | Modified | `url.URL` + `url.Values` for OTP URI |
| `daemon/daemon.go` | Modified | Panic recovery, 300s lockout, `[]byte` pw, TOCTOU |
| `sync/client.go`, `cli/sync.go` | Modified | HTTPS enforcement, masked key, `--insecure` |
| `keychain/keychain_linux.go` | Modified | Encrypted D-Bus session |
| `cli/root.go` | Modified | Persistent rate-limit file |
| `cli/import.go` | Modified | Rename `errors` → `errCount` |
| `gui/app.go` | Modified | Log keychain errors |
| `cli/init.go` | Modified | Explicit `--save-recovery` path |
| `version/version.go` | New | Shared version |
| `cli/exitcodes.go` | New | Shared exit codes |
| `syncserver/routes.go` | New | Route/env constants |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|-------------|
| Argon2 param change breaks old vaults | Low | Fallback to defaults |
| `[]byte` password breaks JSON clients | Low | JSON unmarshals into `[]byte` |
| Encrypted D-Bus unsupported on old distros | Med | Graceful fallback to `plain` |

## Rollback Plan

Revert the PR. Changes are additive/parametric (no schema migrations).

## Dependencies

None.

## Success Criteria

- [ ] All 18 findings have regression tests
- [ ] `go test ./...` passes before every commit
- [ ] Unlock works with old and new vaults
- [ ] Daemon survives panic injection
- [ ] Sync client rejects `http://` without `--insecure`
