# Design: Extend `vlt check` with Password Security Analysis

## Technical Approach

Extract the GUI Watchtower analysis logic into a new `internal/watchtower/` package, then wire it into both the GUI (`app.go`) and CLI (`check.go`). The CLI gains an opt-in `--passwords` flag that unlocks the vault and runs the shared analysis. Metadata checks remain passwordless and unchanged.

## Architecture Decisions

| Decision | Choice | Alternatives | Rationale |
|----------|--------|--------------|-----------|
| Package name | `internal/watchtower/` | `internal/analysis/` | Aligns with the user-facing GUI feature name; unambiguous |
| Engine passing | `*crypto.Engine` parameter | Global singleton | Matches existing `gui/app.go` pattern; enables test injection |
| Store interface | Accept `store.Store` interface | Accept `*store.SQLStore` | Keeps package decoupled; matches existing Store abstraction |
| Zeroization caller | Inside `watchtower.Analyze` | Caller zeroizes | Centralizes security invariant; audit-friendly |
| Error strategy | `store.List()` → hard error; per-secret → continue | Fail on any decryption error | Mirrors current GUI behavior; one bad secret shouldn't block the whole report |

## Data Flow

```
  vlt check --passwords
         │
         ▼
  ┌──────────────┐    locked?    ┌──────────────┐
  │  cli/check   │ ────────────► │ unlockVault  │
  └──────────────┘               └──────────────┘
         │                              │
         │ key                          │ store + key
         ▼                              ▼
  ┌──────────────┐               ┌──────────────┐
  │ metadata     │               │ watchtower.  │
  │ checks       │               │ Analyze      │
  │ (always)     │               │              │
  └──────────────┘               └──────────────┘
         │                              │
         │ issuesFound                  │ *WatchtowerResult
         ▼                              ▼
  ┌──────────────┐               ┌──────────────┐
  │ stderr       │ ◄──────────── │ format &     │
  │ output       │   aggregate   │ print        │
  └──────────────┘               └──────────────┘
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `internal/watchtower/watchtower.go` | Create | Types (`PasswordStrength`, findings, `WatchtowerResult`) and `Analyze` / `AssessPasswordStrength` |
| `internal/watchtower/watchtower_test.go` | Create | Unit tests for strength scoring, reuse, 2FA, and zeroization audit |
| `internal/gui/app.go` | Modify | Remove private types and `assessPasswordStrength`; delegate `AnalyzePasswords` to `watchtower.Analyze` |
| `internal/cli/check.go` | Modify | Add `--passwords` flag, conditional unlock, result formatting to stderr |
| `internal/cli/cli_test.go` | Modify | Integration tests for `--passwords` on locked vault, with/without findings |

## Interfaces / Contracts

```go
package watchtower

func Analyze(s store.Store, eng *crypto.Engine, key []byte) (*WatchtowerResult, error)
func AssessPasswordStrength(password string) (PasswordStrength, string)
```

- `Analyze` returns an error only if `s.List()` fails. Per-secret decryption errors are silently skipped (logged in future if logging is added).
- `AssessPasswordStrength` does not depend on `store` or `crypto`; it is a pure function.
- `PasswordStrength` retains its `String()` and `ColorHex()` methods so the GUI needs zero rendering changes.

## Refactor Plan

1. **Move types and logic** to `internal/watchtower/watchtower.go`:
   - Copy `PasswordStrength` enum, `String()`, `ColorHex()`.
   - Copy `WeakPasswordFinding`, `DuplicatePasswordFinding`, `Missing2FAFinding`, `WatchtowerResult`.
   - Copy `assessPasswordStrength` → `AssessPasswordStrength` (exported).
   - Copy `AnalyzePasswords` body → `Analyze` (accepts `store.Store`, `*crypto.Engine`, `key`).
   - Move `sha256Sum` helper (unexported).

2. **Update `gui/app.go`**:
   - Add `import "github.com/raynosc/vlt/internal/watchtower"`.
   - Replace `AnalyzePasswords` body with a call to `watchtower.Analyze(a.store, a.engine, a.key)`.
   - Delete private types and `assessPasswordStrength`/`sha256Sum`.
   - Keep `PasswordStrengthColor` and `PasswordStrengthLabel` if they exist elsewhere; otherwise alias to `watchtower.PasswordStrength` methods.

3. **Update `cli/check.go`**:
   - Add `--passwords` bool flag with help text stating vault unlock is required.
   - After metadata checks, if `--passwords`:
     - Call `unlockVault(vaultPath)` → `s, key, err`.
     - Call `watchtower.Analyze(s, engine, key)`.
     - Print weak passwords, duplicates, missing 2FA to stderr.
     - Add password-issue counts to `issuesFound`.
   - Preserve existing `issuesFound` aggregation and exit behavior.

## Memory Safety

`watchtower.Analyze` preserves the current zeroization strategy:

1. After `engine.Decrypt`, convert `plaintext` to `string`, then `crypto.Zeroize(plaintext)` immediately.
2. Accumulate decrypted password strings in a local slice for reuse detection.
3. After reuse detection completes, overwrite every entry in the slice with `""` (as the current GUI does at lines 818–821).
4. Return only aggregated results (hashes, counts, metadata); no plaintext leaves the function.

This is best-effort (Go GC may copy strings), but it matches the existing security contract.

## Error Handling

| Layer | Error | Action |
|-------|-------|--------|
| `cli/check` | `--passwords` + unlock fails | Return error (exits non-zero) |
| `watchtower.Analyze` | `store.List()` fails | Return wrapped error |
| `watchtower.Analyze` | `GetByName` / `Decrypt` / `unpackEnvelope` fail | Continue to next secret (do not fail entire analysis) |
| `cli/check` | `watchtower.Analyze` returns error | Return wrapped error (exits non-zero) |

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | `AssessPasswordStrength` boundaries | Table-driven tests: empty, common, short, fair, strong, very strong |
| Unit | Reuse detection | 0 duplicates, 1 unique, 2+ shared passwords |
| Unit | Missing 2FA | With OTPAuth, without OTPAuth, missing URL |
| Unit | Zeroization audit | Mock `crypto.Zeroize` or inspect via `unsafe`/reflection to assert called on decrypted buffers |
| Integration | `vlt check` without `--passwords` | Locked vault passes, no prompt, identical output |
| Integration | `vlt check --passwords` | Unlocked vault with weak/reuse/2FA findings prints to stderr |
| Integration | `vlt check --passwords` empty vault | No password section output, metadata checks still run |
| Regression | Pre-change output format | Existing `TestCheck_*` assertions continue to pass |

## Migration / Rollout

No migration required. The `--passwords` flag is additive and defaults to `false`. Rollback: revert the branch or remove `--passwords` handling from `check.go`.

## Open Questions

- None
