# Design: Security Audit Fixes

## Technical Approach

Apply 13 targeted, per-finding patches across `syncserver`, `daemon`, `cmd/vlt-quick`, `tui`, `gui`, `cli`, `store`, and `crypto`. No schema changes, no new features. The change is purely defensive: close auth gaps, eliminate fail-open paths, plug goroutine/resource leaks, replace panics with errors, and deduplicate hard-coded constants.

## Architecture Decisions

| Decision | Choice | Alternatives | Rationale |
|----------|--------|--------------|-----------|
| Vault UUID authz | Inline check in `handlePush`/`handlePull` — read `ContextKeyVaultUUID` from request header (set by `Authenticate`), compare with `r.PathValue("uuid")`, return 403 on mismatch | Middleware wrapper | Path UUID is handler-specific; inline keeps the contract visible and avoids adding middleware indirection for a one-line check |
| Registration rate limit | Separate `map[string]rateBucket` on `AuthMiddleware` keyed by `r.RemoteAddr`, cleaned with same window logic as API-key limiter | External Redis / IPTables | In-process map is sufficient for a single-server SQLite deployment; no new dependencies |
| TUI plaintext type | Change `model.plaintext` to `[]byte`; display via `string(m.plaintext)`; zeroize with `crypto.Zeroize(m.plaintext)` | Keep `string` and accept GC copies | `[]byte` is the project's existing zeroization contract; `Zeroize` only works on slices |
| HOTP counter race | Add `IncrementHOTPCounter(name string) (uint64, error)` on `SQLStore`; does `BEGIN; SELECT counter; UPDATE counter; COMMIT` | `sync.Mutex` in CLI layer | Store already holds `s.mu`; a single transaction is atomic across connections and matches SQLite concurrency model |
| Recovery panic | Return `fmt.Errorf` from `encodeMnemonic` | Keep panic as "impossible" | Panic in crypto path is unacceptable; callers already handle errors from `GenerateRecoveryKit` |
| Shared colors | `internal/theme/colors.go` with hex strings for TUI/lipgloss and `color.NRGBA` for Fyne | Two separate packages | One source of truth; both formats are compile-time constants |
| Shared charset | `internal/crypto/charset.go` with `DefaultPasswordCharset` | `internal/shared` | Crypto already owns password generation; keeping charset near `Zeroize` reinforces the security boundary |

## Data Flow

```
Client ──► POST /v1/vaults/{uuid}/push
              │
              ▼
    ┌─────────────────┐
    │  Authenticate   │──► validates Bearer token
    │   middleware    │──► stores vault UUID in request header
    └─────────────────┘
              │
              ▼
    ┌─────────────────┐
    │   handlePush    │──► reads path UUID
    │                 │──► reads header UUID
    │                 │──► compares; 403 if mismatch
    └─────────────────┘
              │
              ▼
         ServerStore
```

Registration rate limit follows the same flow but checks `r.RemoteAddr` before `CreateVault`.

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `internal/syncserver/handler.go` | Modify | Add vault UUID authz check in `handlePush` and `handlePull`; add per-IP rate-limit check in `handleRegister` |
| `internal/syncserver/server.go` | Modify | Change `DefaultServerConfig` addr to `localhost:8443`; add `os.Chmod(cfg.DBPath, 0o600)` after `store.Init` |
| `internal/syncserver/auth.go` | Modify | Add `registerLimits map[string]rateBucket` and `rateLimitRegister` method; wire into `handleRegister` |
| `internal/daemon/peer_darwin.go` | Modify | Change `return true` to `return false` on `GETSOCKOPT` failure (lines 59–62) |
| `internal/daemon/daemon.go` | Modify | Add `readyOnce sync.Once` field; replace `close(d.Ready)` with `d.readyOnce.Do(func() { close(d.Ready) })` |
| `cmd/vlt-quick/main.go` | Modify | Move `cmd.Wait()` into the stderr-reading goroutine, after the scanner loop |
| `internal/tui/model.go` | Modify | Change `plaintext string` to `plaintext []byte` in `model` struct |
| `internal/tui/detail.go` | Modify | Update all `m.plaintext` usages to `[]byte` semantics; zeroize via `crypto.Zeroize` |
| `internal/gui/gui.go` | Modify | Add `totpCancel context.CancelFunc` to `GUI`; cancel previous context before spawning new TOTP goroutine in `buildDetailView`; use `ctx.Done()` in goroutine |
| `internal/gui/app.go` | Modify | Consider `GetSecret` returning `[]byte` plaintext (out of scope for this change; noted for follow-up) |
| `internal/cli/totp.go` | Modify | Replace direct `UpdateMetadata` counter increment with `s.IncrementHOTPCounter(name)` |
| `internal/store/store.go` | Modify | Add `IncrementHOTPCounter(name string) (uint64, error)` method with atomic `BEGIN; SELECT; UPDATE; COMMIT` |
| `internal/crypto/recovery.go` | Modify | Change `panic` in `encodeMnemonic` to `return "", fmt.Errorf(...)`; update `GenerateRecoveryKit` caller to propagate error |
| `internal/theme/colors.go` | **Create** | Named constants: `ColorPrimary`, `ColorPrimaryRGBA`, etc. for hex and `color.NRGBA` |
| `internal/crypto/charset.go` | **Create** | `DefaultPasswordCharset` constant |
| `internal/tui/model.go` | Modify | Replace hard-coded hex colors with `theme.ColorPrimary` etc. |
| `internal/tui/generate.go` | Modify | Import `crypto.DefaultPasswordCharset` |
| `internal/gui/gui.go` | Modify | Replace hard-coded `color.RGBA`/`color.NRGBA` values with `theme.ColorPrimaryRGBA` etc. |
| `internal/quick/quick.go` | Modify | Replace hard-coded hex colors with theme constants |
| `internal/daemon/daemon.go` | Modify | Import `crypto.DefaultPasswordCharset` in `generatePassword` |
| `internal/gui/app.go` | Modify | Import `crypto.DefaultPasswordCharset` in `GeneratePassword` |

## Interfaces / Contracts

```go
// internal/theme/colors.go
package theme

const (
    ColorPrimary     = "#7C3AED"
    ColorSuccess     = "#16A34A"
    ColorError       = "#DC2626"
    ColorWarning     = "#F59E0B"
    ColorDim         = "#888888"
    ColorHelp        = "#636363"
    ColorLabel       = "#A1A1AA"
    ColorSeparator   = "#333333"
)

var (
    ColorPrimaryRGBA   = color.NRGBA{0x7C, 0x3A, 0xED, 0xFF}
    ColorSuccessRGBA   = color.NRGBA{0x10, 0xB9, 0x81, 0xFF}
    ColorErrorRGBA     = color.NRGBA{0xEF, 0x44, 0x44, 0xFF}
    // ... etc
)
```

```go
// internal/crypto/charset.go
package crypto

const DefaultPasswordCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/~"
```

```go
// internal/store/store.go — new method
func (s *SQLStore) IncrementHOTPCounter(name string) (uint64, error)
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | Vault UUID mismatch → 403 | `httptest` with forged `ContextKeyVaultUUID` header |
| Unit | Registration rate limit → 429 | Rapid-fire `httptest` from same IP |
| Unit | `sync.Once` double-close guard | Call `Run()` twice in test, assert no panic |
| Unit | HOTP counter increment atomicity | Two concurrent goroutines; verify final counter = 2 |
| Unit | `encodeMnemonic` wrong length → error | Pass 31-byte key, expect error (was panic) |
| Integration | `go test ./...` | Zero regressions |
| Lint | `golangci-lint` | Zero new warnings |

## Migration / Rollout

No migration required. All changes are backward-compatible fixes with no schema changes.

## Open Questions

- None.
