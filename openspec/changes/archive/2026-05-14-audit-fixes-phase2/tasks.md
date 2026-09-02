# Tasks: Audit Fixes Phase 2

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~700–950 |
| 400-line budget risk | High |
| Chained PRs recommended | No |
| Suggested split | size-exception single PR |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: High

## Phase 1: Crypto & Data Integrity

- [x] 1.1 RED: Write failing test for `crypto.NewEngine` functional options
- [x] 1.2 GREEN: Add functional options to `crypto.NewEngine` in `internal/crypto/engine.go`
- [x] 1.3 RED: Write failing test for Argon2 read-back in CLI unlock
- [x] 1.4 GREEN: Read stored Argon2 params in `cli/root.go` `unlockVault`
- [x] 1.5 RED: Write failing test for Argon2 read-back in daemon unlock
- [x] 1.6 GREEN: Read stored Argon2 params in `daemon/daemon.go` `handleUnlock`
- [x] 1.7 RED: Write failing test for Argon2 read-back in GUI unlock
- [x] 1.8 GREEN: Read stored Argon2 params in `gui/app.go` `Unlock`
- [x] 1.9 RED: Write failing test for `PathUnescape` in `otp/uri.go`
- [x] 1.10 GREEN: Fix `PathEscape`→`PathUnescape` in `internal/otp/uri.go`
- [x] 1.11 RED: Write failing test for `time.Parse` error propagation in `store/store.go`
- [x] 1.12 GREEN: Propagate `time.Parse` errors in `internal/store/store.go`
- [x] 1.13 RED: Write failing test for safe OTP URI construction in `gui/gui.go`
- [x] 1.14 GREEN: Fix OTP URI construction using `url.URL`+`url.Values` in `gui/gui.go`

## Phase 2: Daemon Hardening

- [x] 2.1 RED: Write failing test for panic recovery in `handleConnection`
- [x] 2.2 GREEN: Add `defer recover()` in `daemon/daemon.go` `handleConnection`
- [x] 2.3 RED: Write failing test for progressive lockout (300s+ escalation)
- [x] 2.4 GREEN: Increase lockout to 300s with progressive backoff in daemon
- [x] 2.5 RED: Write failing test for `[]byte` password zeroization
- [x] 2.6 GREEN: Change `Request.Password` `string`→`[]byte`, zeroize after unlock
- [x] 2.7 RED: Write failing test for TOCTOU symlink guard on socket path
- [x] 2.8 GREEN: Add TOCTOU check before `os.Remove` socket path
- [x] 2.9 Run full daemon test suite after first pass
- [x] 2.10 Run full daemon test suite after all daemon changes

## Phase 3: Sync Security

- [x] 3.1 RED: Write failing test for HTTPS enforcement in `sync.NewClient`
- [x] 3.2 GREEN: Enforce HTTPS in `NewClient`, add `NewClientInsecure` to `sync/client.go`
- [x] 3.3 RED: Write failing test for `--insecure` flag in sync CLI
- [x] 3.4 GREEN: Add `--insecure` flag to sync commands in `cli/sync.go`
- [x] 3.5 RED: Write failing test for API key masking and `show-key`
- [x] 3.6 GREEN: Mask API key output, add `sync show-key` command
- [x] 3.7 RED: Write failing test for encrypted D-Bus session fallback
- [x] 3.8 GREEN: Implement encrypted D-Bus session in `keychain_linux.go` with `plain` fallback
- [x] 3.9 Run sync + keychain test suites

## Phase 4: CLI/Store Robustness

- [x] 4.1 RED: Write failing test for persistent rate limit file
- [x] 4.2 GREEN: Create `internal/cli/lockout.go` with persistent JSON rate limit
- [x] 4.3 GREEN: Integrate lockout into `cli/root.go` `unlockVault` flow
- [x] 4.4 GREEN: Rename `errors`→`errCount` in `cli/import.go`
- [x] 4.5 GREEN: Log keychain errors in `gui/app.go`
- [x] 4.6 RED: Write failing test for `--save-recovery` path validation
- [x] 4.7 GREEN: Change `--save-recovery` to string flag with path validation in `cli/init.go`
- [x] 4.8 Run cli + gui test suites

## Phase 5: Structural Constants

- [x] 5.1 GREEN: Create `internal/version/version.go` with `Version` constant
- [x] 5.2 GREEN: Update daemon and gui to import shared version
- [x] 5.3 GREEN: Create `internal/cli/exitcodes.go`, update all 5 `cmd/*/main.go`
- [x] 5.4 GREEN: Create `internal/syncserver/routes.go`, update `handler.go` + `cli/sync.go`
- [x] 5.5 Run full test suite `go test ./...` and `golangci-lint run ./...`
