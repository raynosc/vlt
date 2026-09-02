## Exploration: Extend `vlt check` with Password Security Analysis

### Current State
`vlt check` (`internal/cli/check.go`) performs two metadata-only checks without unlocking the vault:
1. **Duplicate names** — iterates `s.List()`, counts occurrences.
2. **Expiring certificates** — calls `s.ListExpiring(days)`.

The GUI already has a full-featured Watchtower in `internal/gui/app.go:696-824` (`AnalyzePasswords`) that:
- Decrypts all `KindPassword` secrets via `store.GetByName` + `engine.Decrypt`.
- Scores password strength (`assessPasswordStrength`, lines 833-939).
- Detects reused/duplicate passwords across entries (SHA-256 hash grouping).
- Detects missing 2FA (passwords with a URL but no `OTPAuth` metadata).
- Counts expiring certificates.

All analysis types (`PasswordStrength`, `WeakPasswordFinding`, `DuplicatePasswordFinding`, `Missing2FAFinding`, `WatchtowerResult`) and the strength algorithm are **private to `internal/gui`**. The CLI has no access to them.

`vlt get` (`internal/cli/get.go`) shows the canonical unlock pattern: `s, key, err := unlockVault(vaultPath)`.

`store.List()` returns metadata-only secrets (`EncryptedValue` is explicitly nil, line 431). To decrypt values, the analyzer must fall back to `store.GetByName(name)` for each password secret, exactly as the GUI already does.

### Affected Areas
| File | Why |
|------|-----|
| `internal/cli/check.go` | Add `--passwords` flag, conditional vault unlock, password analysis output |
| `internal/gui/app.go` | Extract `AnalyzePasswords`, strength types, and assessment logic |
| `internal/cli/cli_test.go` | Add integration tests for `--passwords` behavior |
| `internal/cli/root.go` | No changes needed — `unlockVault`, `engine`, `unpackEnvelope` already exported/package-level |
| `internal/secret/secret.go` | No changes needed — `PasswordMetadata` and helpers already here |
| `internal/store/store.go` | No changes needed — `GetByName` already returns full ciphertext |
| **NEW** `internal/watchtower/` (or `internal/analysis/`) | Shared package for `WatchtowerResult`, `assessPasswordStrength`, and `Analyze(store, engine, key)` |

### Approaches

#### 1. Extract Shared Package + Add `--passwords` Flag (Recommended)
Create `internal/watchtower/` containing:
- `WatchtowerResult`, `WeakPasswordFinding`, `DuplicatePasswordFinding`, `Missing2FAFinding`
- `PasswordStrength` enum + `assessPasswordStrength(password string) (PasswordStrength, string)`
- `Analyze(s store.Store, eng *crypto.Engine, key []byte) (*WatchtowerResult, error)`

Update `gui/app.go` to delegate `AnalyzePasswords` to `watchtower.Analyze`.
Update `cli/check.go`:
- Add `--passwords bool` flag (default `false`).
- When true, call `unlockVault(vaultPath)` then `watchtower.Analyze`.
- Print findings to stderr in human-readable format (mirroring existing check style).
- Keep existing metadata-only checks always enabled.

| Aspect | Detail |
|--------|--------|
| **Pros** | No duplication; backward compatible; clean separation of concerns; GUI and CLI stay in sync; easy to test shared logic in isolation |
| **Cons** | Touches two major packages; requires careful zeroization of decrypted buffers in shared code |
| **Effort** | **Medium** |

#### 2. Inline Analysis Directly in `cli/check.go`
Copy the relevant logic from `gui/app.go` into `cli/check.go` without extracting a shared package.

| Aspect | Detail |
|--------|--------|
| **Pros** | Fastest to implement; no risk of breaking GUI |
| **Cons** | Duplicates ~120 LOC of analysis + types; diverges when GUI updates; violates DRY |
| **Effort** | **Low** |

#### 3. Make Password Analysis the Default Behavior
Always unlock and run full analysis in `vlt check`.

| Aspect | Detail |
|--------|--------|
| **Pros** | Simplest UX — one command does everything |
| **Cons** | **Breaking change**: breaks scripts/automation that rely on check being passwordless; changes the command's security contract; unexpected prompt in CI/CD |
| **Effort** | **Low** (code), **High** (user impact) |

### Recommendation
**Approach 1 — Extract `internal/watchtower/` + `--passwords` flag.**

Rationale:
- The GUI already proved the analysis logic is reusable.
- A shared package prevents the classic "GUI and CLI diverge" bug.
- Making it opt-in (`--passwords`) preserves the current no-password contract, which is documented in the command help text and likely relied upon by users.
- The `--passwords` name is self-documenting and mirrors the concept users already know from the GUI Watchtower.

### Estimated Scope / Complexity
- **New package**: `internal/watchtower/watchtower.go` (~150 LOC moved from `gui/app.go`) + `watchtower_test.go` (~100 LOC)
- **GUI refactor**: `internal/gui/app.go` — replace private types and `AnalyzePasswords` body with calls to `watchtower` (~30 LOC changed)
- **CLI changes**: `internal/cli/check.go` — add flag, conditional unlock, result formatting (~60 LOC)
- **CLI tests**: `internal/cli/cli_test.go` — 2-3 new test cases (~80 LOC)
- **Total changed lines**: ~250-350 (well within 400-line budget)
- **Chained PRs needed**: No

### Key Files to Touch
1. `internal/watchtower/watchtower.go` (new)
2. `internal/watchtower/watchtower_test.go` (new)
3. `internal/gui/app.go` (refactor `AnalyzePasswords`)
4. `internal/cli/check.go` (add `--passwords`)
5. `internal/cli/cli_test.go` (new tests)

### Risks
1. **GUI regression** — If `watchtower.Analyze` signature or behavior differs subtly, the GUI Watchtower screen could break. Mitigation: keep the same return types and zeroization logic.
2. **Memory safety** — Decrypted passwords must be explicitly zeroized (`crypto.Zeroize`) after analysis. The GUI does this today; the shared package must preserve it.
3. **Master password prompt surprise** — Users running `vlt check` in scripts will not be affected (flag is opt-in), but users who *do* add `--passwords` must be ready for a prompt. The help text and long description should make this clear.
4. **`List()` metadata-only caveat** — `store.List()` skips `encrypted_value`. The analyzer must call `GetByName` per password secret. This is N+1 but acceptable for a vault-check command (typically < 1000 secrets). If performance becomes an issue later, `store.ListFull()` could be added, but that's out of scope.

### Open Questions
1. **Should `--passwords` also suppress metadata-only checks?** No — keep them; they are cheap and useful even when the vault is empty of passwords.
2. **Output format** — Should `--json` be supported for password analysis? Not in the first slice; the GUI doesn't expose JSON export for Watchtower either. Can be added later.
3. **Package name** — `watchtower` is GUI-branded. `analysis` or `security` is more CLI-neutral. Suggest `internal/watchtower/` because it aligns with the user-facing feature name and is unambiguous.

### Ready for Proposal
**Yes.** The scope is clear, the existing code provides a blueprint, and the extraction surface is well bounded. The orchestrator can proceed to `sdd-propose`.
