## Verification Report

**Change**: audit-fixes-phase2
**Version**: N/A
**Mode**: Standard

### Completeness
| Metric | Value |
|--------|-------|
| Tasks total | 30 |
| Tasks complete | 30 |
| Tasks incomplete | 0 |

### Build & Tests Execution
**Build**: ✅ Passed
```text
$ go build ./...
# github.com/raynosc/vlt/cmd/vlt-gui
ld: warning: ignoring duplicate libraries: '-lobjc'
```
(Linker warning is pre-existing on macOS; not caused by this change.)

**Tests**: ✅ All passed / ❌ 0 failed / ⚠️ 0 skipped
```text
$ go test ./...
ok  	github.com/raynosc/vlt/internal/cli	(cached)
ok  	github.com/raynosc/vlt/internal/config	(cached)
ok  	github.com/raynosc/vlt/internal/crypto	(cached)
ok  	github.com/raynosc/vlt/internal/daemon	5.236s
ok  	github.com/raynosc/vlt/internal/gui	(cached)
ok  	github.com/raynosc/vlt/internal/keychain	(cached)
ok  	github.com/raynosc/vlt/internal/otp	(cached)
ok  	github.com/raynosc/vlt/internal/parse	(cached)
ok  	github.com/raynosc/vlt/internal/quick	(cached)
ok  	github.com/raynosc/vlt/internal/secret	(cached)
ok  	github.com/raynosc/vlt/internal/store	(cached)
ok  	github.com/raynosc/vlt/internal/sync	(cached)
ok  	github.com/raynosc/vlt/internal/syncserver	(cached)
ok  	github.com/raynosc/vlt/internal/tui	(cached)
ok  	github.com/raynosc/vlt/internal/version	(cached)
```

**Coverage**: ➖ Not available

**Lint**: ⚠️ 10 pre-existing issues only (no new issues)
```text
$ golangci-lint run ./...
internal/syncserver/server_test.go:211:22: errcheck
internal/syncserver/server_test.go:218:21: errcheck
internal/gui/app_test.go:323:2: SA9003
internal/gui/app_test.go:1157:2: SA9003
internal/gui/app_test.go:1210:2: SA9003
internal/gui/gui.go:572:19: SA1019
internal/gui/gui.go:585:22: SA1019
internal/gui/gui.go:657:2: S1011
internal/gui/gui.go:662:3: S1011
internal/gui/gui.go:745:6: unused
```

### Spec Compliance Matrix
| Requirement | Scenario | Test | Result |
|-------------|----------|------|--------|
| Argon2 Parameter Fidelity | Unlock with custom params | `TestDaemon_UnlockWithCustomArgon2Params` | ✅ COMPLIANT |
| Argon2 Parameter Fidelity | Unlock legacy vault | Implicit fallback in all unlock tests | ✅ COMPLIANT |
| OTP Label Path Unescaping | Escaped label in URI | `TestParseOTPURI_EscapedLabel` | ✅ COMPLIANT |
| OTP Label Path Unescaping | Plain label unchanged | `TestParseOTPURI_LabelParsing` | ✅ COMPLIANT |
| Timestamp Parse Error Propagation | Corrupted timestamp | `TestGetByName_MalformedTimestamp_ReturnsError` | ✅ COMPLIANT |
| Timestamp Parse Error Propagation | Valid timestamp succeeds | All store integration tests | ✅ COMPLIANT |
| Safe OTP URI Construction | Secret name with query character | `TestBuildOTPAuthURI_EncodesSpecialChars` | ✅ COMPLIANT |
| Safe OTP URI Construction | Standard name encoded correctly | `TestBuildOTPAuthURI_StandardName` | ✅ COMPLIANT |
| Panic Recovery in Connection Handler | Panic in handler | `TestDaemon_PanicRecovery` | ✅ COMPLIANT |
| Progressive Lockout | Five failed attempts trigger lockout | `TestDaemon_ProgressiveLockout` | ✅ COMPLIANT |
| Progressive Lockout | Lockout resets after success | `TestDaemon_UnlockLock` | ✅ COMPLIANT |
| Master Password Zeroization | Password cleared after unlock | `TestDaemon_UnlockZeroizesPassword` | ✅ COMPLIANT |
| TOCTOU-Safe Socket Creation | Symlink at socket path | `TestDaemon_TOCTOU_Symlink` | ✅ COMPLIANT |
| TLS Enforcement on Sync Client | HTTP URL rejected | `TestNewClient_RejectsHTTP` | ✅ COMPLIANT |
| TLS Enforcement on Sync Client | HTTPS URL accepted | `TestClient_PushPull_RoundTrip` | ✅ COMPLIANT |
| TLS Enforcement on Sync Client | Insecure flag bypasses check | `TestNewClientInsecure_AllowsHTTP` | ✅ COMPLIANT |
| API Key Masking | sync init prints masked key | `TestSyncInit_MasksAPIKey` | ⚠️ PARTIAL (terminal masked; JSON mode exposes full key) |
| Encrypted D-Bus Session | Encrypted session opened | Implementation evidence (Linux-only) | ✅ COMPLIANT |
| Encrypted D-Bus Session | Graceful fallback | Implementation evidence (Linux-only) | ✅ COMPLIANT |
| Persistent Rate Limiting | Lockout survives restart | `TestLockout_SurvivesRestart` | ✅ COMPLIANT |
| Package Shadowing Elimination | Build verification | `go build ./...` | ✅ COMPLIANT |
| Keychain Error Observability | Keychain failure logged | `app.go:116` | ✅ COMPLIANT |
| Recovery Kit Path Safety | Missing path errors | Cobra string-flag validation | ✅ COMPLIANT |
| Recovery Kit Path Safety | Explicit path succeeds | `TestInit_RecoveryKitToFile` | ✅ COMPLIANT |
| Single Version Source of Truth | Version consistency | `TestVersion` | ⚠️ PARTIAL (vlt CLI uses local `Version`) |
| Named Exit Code Constants | Error exit uses constant | All `cmd/*/main.go` | ✅ COMPLIANT |
| API Path Constants | Routes use constants | `TestRoutes` + `handler.go` | ✅ COMPLIANT |
| API Path Constants | Route constant consistency | `TestRoutes` | ✅ COMPLIANT |

**Compliance summary**: 26/28 scenarios fully compliant, 2 partial.

### Correctness (Static Evidence)
| Requirement | Status | Notes |
|------------|--------|-------|
| Argon2 read-back (CLI) | ✅ Implemented | `cli/root.go` `readArgon2Params` + `unlockVault` |
| Argon2 read-back (daemon) | ✅ Implemented | `daemon/daemon.go` `readArgon2Params` + `handleUnlock` |
| Argon2 read-back (GUI) | ✅ Implemented | `gui/app.go` `readArgon2Params` + `Unlock` |
| OTP PathUnescape | ✅ Implemented | `otp/uri.go:77-78` |
| time.Parse propagation | ✅ Implemented | `store/store.go:360-367,433-439` |
| OTP URI safe construction | ✅ Implemented | `gui/gui.go:231-242` |
| Daemon panic recovery | ✅ Implemented | `daemon/daemon.go:269-279` |
| Progressive lockout | ✅ Implemented | `daemon/daemon.go:41-42,401-410` |
| []byte password zeroization | ✅ Implemented | `daemon/daemon.go:45-76,423-427` |
| TOCTOU socket guard | ✅ Implemented | `daemon/daemon.go:153-158` |
| TLS enforcement | ✅ Implemented | `sync/client.go:47-49,68-76` |
| API key masking (terminal) | ✅ Implemented | `cli/sync.go:40-45,205` |
| Encrypted D-Bus session | ✅ Implemented | `keychain/keychain_linux.go:37-63` |
| Persistent rate limit file | ✅ Implemented | `cli/lockout.go` + `root.go:258-260` |
| errCount rename | ✅ Implemented | `cli/import.go:122` |
| Keychain error logging | ✅ Implemented | `gui/app.go:116` |
| Recovery kit string flag | ✅ Implemented | `cli/init.go:32,43,178-192` |
| Shared version constant | ⚠️ Partial | `version/version.go` exists; `cli/root.go:51` still defines local `Version` |
| Exit code constants | ✅ Implemented | `cli/exitcodes.go` + all `cmd/*/main.go` |
| API route constants | ✅ Implemented | `syncserver/routes.go` + `handler.go` |

### Coherence (Design)
| Decision | Followed? | Notes |
|----------|-----------|-------|
| Argon2 Params Read-Back | ✅ Yes | Fallback to defaults preserves old vaults |
| Daemon Password as []byte | ✅ Yes | Custom `UnmarshalJSON` for wire compat |
| Progressive Lockout | ✅ Yes | 5m → 15m → 1h escalation |
| TLS Enforcement | ✅ Yes | `NewClient`/`NewClientInsecure` split mirrors design |
| Encrypted D-Bus Session | ✅ Yes | Try encrypted, fallback to plain with warning |

### Issues Found
**CRITICAL**: None

**WARNING**:
1. **`internal/cli/root.go` uses local `Version` instead of shared constant**  
   `cli/root.go:51` defines `var Version = "0.2.1"`. The `vlt` binary (`cmd/vlt`) reports this local variable via `newRootCmd().Version`, not `internal/version.Version`. Only `vlt-gui` (`cmd/vlt-gui`) correctly uses the shared constant through `gui.Version`. This violates the spec requirement that all binaries derive their version from a single shared source.

2. **TUI does not read stored Argon2 parameters**  
   `cmd/vlt-tui/main.go:96` creates `crypto.NewEngine(nil)` and never reads stored Argon2 config keys. The spec states the engine must read stored params during unlock. While all currently-created vaults use default params (init stores defaults), this is a consistency gap that will break custom-param vaults in the TUI.

3. **`vlt sync init --json` outputs full unmasked API key**  
   In `cli/sync.go:195`, the JSON output object includes `"api_key": hexKey` (full key). The terminal (stderr) output is correctly masked with `maskKey`, but machine-readable JSON mode bypasses masking. The spec states "The CLI MUST mask API keys in output" without exempting JSON.

**SUGGESTION**:
1. **Zeroize transient `[]byte(password)` in GUI unlock**  
   `gui/app.go:170,174` converts the password string to `[]byte` twice but never calls `crypto.Zeroize` on the temporary slices. While Go strings are immutable, clearing the transient allocations adds defense in depth.
2. **Unify version reporting**  
   Replace `cli/root.go:51` with `var Version = version.Version` (add import) so the `vlt` CLI uses the same shared constant as `vlt-gui`.

### Verdict
**PASS WITH WARNINGS**

All 30 tasks are complete, all 14+ test suites pass, build succeeds, and no new lint issues were introduced. The three warnings are design/spec deviations that do not break existing vaults or crash the daemon, but should be addressed before final release:
1. vlt CLI version not using shared constant;
2. TUI missing Argon2 param read-back;
3. JSON mode in `sync init` exposing the full API key.
