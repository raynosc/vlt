# Design: Audit Fixes Phase 2

## Technical Approach

Localized, surgical security patches across 5 groups (crypto, daemon, sync, CLI/store, structural constants). Each finding gets a targeted fix with a regression test. No schema migrations. The approach follows the proposal: parametric changes with safe fallbacks, so old vaults continue to work.

## Architecture Decisions

### Decision: Argon2 Params Read-Back

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Always use defaults | Breaks vaults created with custom params | Reject |
| Read from store, fallback to defaults | One extra query per unlock, safe for old vaults | **Accept** |
| Cache in config file | Adds sync complexity, minimal gain | Reject |

**Rationale**: `unlockVault`, `handleUnlock`, and `gui.App.Unlock` already have the store open. Reading three config keys and parsing `uint32` is negligible overhead. Fallback preserves backward compatibility.

### Decision: Daemon Password as `[]byte`

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Keep `string` | GC may retain password in heap | Reject |
| Change to `[]byte` + `crypto.Zeroize` | Zeroization works; JSON unmarshal supports `[]byte` natively | **Accept** |
| Custom `json.Unmarshaler` | Over-engineered for one field | Reject |

**Rationale**: `encoding/json` unmarshals JSON strings into `[]byte` transparently. After `engine.Unlock()`, call `crypto.Zeroize(req.Password)` before returning.

### Decision: Progressive Lockout

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Fixed 300s | Simple, no state tracking | Reject |
| Progressive (5m → 15m → 1h) | Slightly more state; better brute-force resistance | **Accept** |
| Persistent lockout file | Survives restart; more I/O | Deferred to CLI only (finding #12) |

**Rationale**: Add `consecutiveLockouts int` to `Daemon`. On lockout, increment and compute duration from a slice `[5m, 15m, 1h]`. Reset on successful unlock.

### Decision: TLS Enforcement

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Always require HTTPS | Breaks local dev / testing | Reject |
| Default HTTPS, `NewClientInsecure` opt-in | Explicit unsafe choice, safe default | **Accept** |
| Config flag in store | Harder to discover, more state | Reject |

**Rationale**: `sync.NewClient` rejects `http://`. CLI adds `--insecure` flag that calls `NewClientInsecure`. This mirrors `curl -k` and is obvious in code review.

### Decision: Encrypted D-Bus Session

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Always encrypted | Fails on older Secret Service implementations | Reject |
| Try encrypted, fallback to `plain` with warning | Best compatibility, logs the downgrade | **Accept** |
| Always `plain` (status quo) | Leaves secrets exposed on the bus | Reject |

**Rationale**: Attempt `dh-ietf1024-sha256-aes128-cbc-pkcs7` first. On `dbus.ErrMsgUnknownMethod` or similar, fall back to `plain` and log a warning.

## Data Flow

```
CLI Unlock          Daemon Unlock         GUI Unlock
     │                    │                    │
     ▼                    ▼                    ▼
 openStore()          openStore()          openStore()
     │                    │                    │
     ▼                    ▼                    ▼
 ConfigGet(params)    ConfigGet(params)    ConfigGet(params)
     │                    │                    │
     ▼                    ▼                    ▼
 crypto.NewEngine(?)  crypto.NewEngine(?)  crypto.NewEngine(?)
     │                    │                    │
     └────────────────────┴────────────────────┘
                        │
                        ▼
              Argon2id key derivation
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `internal/version/version.go` | Create | `const Version = "0.2.1"` |
| `internal/cli/exitcodes.go` | Create | `ExitSuccess`, `ExitError`, `ExitCancel` |
| `internal/cli/lockout.go` | Create | Persistent rate-limit JSON file logic |
| `internal/syncserver/routes.go` | Create | Route path constants |
| `internal/crypto/engine.go` | Modify | `NewEngine` already accepts `*Argon2Params`; callers now pass stored params |
| `internal/cli/root.go` | Modify | Read Argon2 params; integrate persistent lockout |
| `internal/daemon/daemon.go` | Modify | Panic recovery, progressive lockout, `[]byte` password, TOCTOU guard |
| `internal/gui/app.go` | Modify | Read Argon2 params; log keychain errors |
| `internal/otp/uri.go` | Modify | `PathUnescape` instead of `PathEscape` |
| `internal/store/store.go` | Modify | Return `time.Parse` errors instead of ignoring them |
| `internal/gui/gui.go` | Modify | `buildOTPAuthURI` helper using `url.URL` + `url.Values` |
| `internal/sync/client.go` | Modify | HTTPS enforcement; `NewClientInsecure` constructor |
| `internal/cli/sync.go` | Modify | Mask API key; `--insecure` flag; `sync show-key` command |
| `internal/keychain/keychain_linux.go` | Modify | Encrypted session attempt with `plain` fallback |
| `internal/cli/import.go` | Modify | Rename `errors` → `errCount` |
| `internal/cli/init.go` | Modify | `--save-recovery` as string flag with path validation |
| `cmd/*/main.go` (5 files) | Modify | Use `internal/cli/exitcodes` constants |

## Interfaces / Contracts

### New Helpers

```go
// internal/cli/lockout.go
func checkLockout(lockoutPath string) (locked bool, remaining time.Duration, err error)
func recordAttempt(lockoutPath string) error
func clearLockout(lockoutPath string) error

// internal/gui/gui.go
func buildOTPAuthURI(name, secret string) string

// internal/sync/client.go
func NewClientInsecure(s *store.SQLStore) (*Client, error)
```

### Daemon Request Change

```go
type Request struct {
    Cmd      string `json:"cmd"`
    Password []byte `json:"password,omitempty"`  // changed from string
    // ...
}
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | Argon2 param read-back | Create vault with custom params, unlock, verify `Engine.params` matches |
| Unit | OTP `PathUnescape` | Table-driven test with escaped labels containing spaces/special chars |
| Unit | `time.Parse` error propagation | Inject malformed `created_at` into DB, assert error returned |
| Unit | OTP URI construction | Assert `buildOTPAuthURI` produces valid, encoded URIs |
| Unit | Daemon panic recovery | Inject panic via test hook, assert error response written, daemon still runs |
| Unit | Progressive lockout | 5 failed unlocks → verify lockout durations escalate |
| Unit | `[]byte` password zeroization | Inspect `Request.Password` after `handleUnlock`; assert all zeros |
| Unit | TOCTOU guard | Create regular file at socket path, assert `Run()` returns error without removing it |
| Unit | TLS enforcement | `NewClient` with `http://` URL → expect error; `NewClientInsecure` → success |
| Unit | API key masking | Assert `syncInit` output contains `****` + last 4 chars |
| Unit | Encrypted D-Bus fallback | Mock `OpenSession` failure → verify `plain` fallback path executed |
| Unit | Persistent lockout | Simulate 5 failed attempts, verify JSON file written, next attempt rejected |
| Unit | Recovery kit path guard | Pass vault dir path → error; pass external path → success with warning |
| Integration | End-to-end unlock | Old vault (no stored params) and new vault both unlock successfully |
| Integration | Sync push/pull | With `--insecure` against local HTTP server → success; without → rejected |

## Migration / Rollout

No migration required. Changes are additive:
- Old vaults missing Argon2 config keys fall back to `DefaultArgon2Params`.
- Daemon `Request.Password` change is wire-format compatible (JSON string → `[]byte`).
- New exit code and version constants are compile-time only.
- Persistent lockout file is created on first failed attempt; no pre-seeding needed.

## Open Questions

- [ ] Should `consecutiveLockouts` in daemon be reset on daemon restart? (Currently yes — in-memory only.)
- [ ] Should `vlt sync show-key` require vault unlock or just store access? (Store access is sufficient — key is in config table.)
- [ ] Should the lockout JSON file be chmod 600? (Recommended — implement in `recordAttempt`.)
