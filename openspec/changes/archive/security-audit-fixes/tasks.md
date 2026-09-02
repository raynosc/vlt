# Tasks: Security Audit Fixes

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~350–450 |
| 400-line budget risk | Medium |
| Chained PRs recommended | No |
| Suggested split | Single PR (size:exception) |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: Medium

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Security audit fixes (all 13 findings) | PR 1 | size:exception; solo developer; tests + lint included |

## Phase 1: Sync Server Security

- [ ] 1.1 **RED**: `internal/syncserver/handler_test.go` — valid key for wrong vault UUID returns 403
- [ ] 1.2 **GREEN**: `internal/syncserver/handler.go` — add vault UUID authz check in `handlePush`/`handlePull`
- [ ] 1.3 **RED**: `internal/syncserver/handler_test.go` — rapid registration from same IP returns 429
- [ ] 1.4 **GREEN**: `internal/syncserver/auth.go` — add `registerLimits` and `rateLimitRegister`; wire into `handleRegister`
- [ ] 1.5 **RED**: `internal/syncserver/server_test.go` — default bind address is `127.0.0.1`
- [ ] 1.6 **GREEN**: `internal/syncserver/server.go` — set `DefaultServerConfig` addr to `localhost:8443`
- [ ] 1.7 **GREEN**: `internal/syncserver/server.go` — `os.Chmod(cfg.DBPath, 0o600)` after `store.Init`
- [ ] 1.8 Commit Phase 1; run `go test ./...`

## Phase 2: Daemon Fixes

- [ ] 2.1 **GREEN**: `internal/daemon/peer_darwin.go` — `return false` on `GETSOCKOPT` failure
- [ ] 2.2 **RED**: `internal/daemon/daemon_test.go` — double `Run()` does not panic
- [ ] 2.3 **GREEN**: `internal/daemon/daemon.go` — guard `close(d.Ready)` with `readyOnce sync.Once`
- [ ] 2.4 **GREEN**: `cmd/vlt-quick/main.go` — move `cmd.Wait()` into stderr-reading goroutine
- [ ] 2.5 Commit Phase 2; run `go test ./...`

## Phase 3: TUI/GUI Memory Safety

- [ ] 3.1 **RED**: `internal/tui/detail_test.go` — `plaintext` is `[]byte` and zeroized on quit
- [ ] 3.2 **GREEN**: `internal/tui/model.go` — change `plaintext string` to `[]byte`; `detail.go` — update usages and call `crypto.Zeroize`
- [ ] 3.3 **RED**: `internal/gui/gui_test.go` — TOTP goroutine terminates on view dismiss
- [ ] 3.4 **GREEN**: `internal/gui/gui.go` — add `totpCancel`; cancel old context before spawn; check `ctx.Done()` in loop
- [ ] 3.5 Commit Phase 3; run `go test ./...`

## Phase 4: CLI/Crypto Robustness

- [ ] 4.1 **RED**: `internal/store/store_test.go` — concurrent `IncrementHOTPCounter` yields unique values
- [ ] 4.2 **GREEN**: `internal/store/store.go` — add `IncrementHOTPCounter(name string) (uint64, error)` with atomic tx
- [ ] 4.3 **GREEN**: `internal/cli/totp.go` — replace `UpdateMetadata` counter with `s.IncrementHOTPCounter`
- [ ] 4.4 **RED**: `internal/crypto/recovery_test.go` — `encodeMnemonic` with 31-byte key returns error
- [ ] 4.5 **GREEN**: `internal/crypto/recovery.go` — change panic to `return "", fmt.Errorf(...)`; update `GenerateRecoveryKit` caller
- [ ] 4.6 Commit Phase 4; run `go test ./...`

## Phase 5: Deduplication

- [ ] 5.1 **GREEN**: Create `internal/theme/colors.go` with hex and `color.NRGBA` constants
- [ ] 5.2 **GREEN**: `internal/tui/model.go`, `internal/quick/quick.go` — import theme colors; remove hard-coded hex
- [ ] 5.3 **GREEN**: `internal/gui/gui.go` — import theme colors; remove hard-coded `color.RGBA`
- [ ] 5.4 **GREEN**: Create `internal/crypto/charset.go` with `DefaultPasswordCharset`
- [ ] 5.5 **GREEN**: `internal/tui/generate.go`, `internal/daemon/daemon.go`, `internal/gui/app.go` — import charset; remove duplicates
- [ ] 5.6 Commit Phase 5; run `go test ./...` and `golangci-lint run ./...`
