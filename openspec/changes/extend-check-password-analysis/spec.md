# Specification: Extend `vlt check` with Password Security Analysis

## Overview

Extract the GUI Watchtower analysis logic into `internal/watchtower/` and expose it to `vlt check` via an opt-in `--passwords` flag.

---

## Domain: watchtower-analysis

### Interface Contract

```go
type PasswordStrength int
const (
    StrengthVeryWeak PasswordStrength = iota
    StrengthWeak
    StrengthFair
    StrengthStrong
    StrengthVeryStrong
)

type WeakPasswordFinding struct {
    SecretName string
    Username   string
    URL        string
    Score      PasswordStrength
    Reason     string
}

type DuplicatePasswordFinding struct {
    PasswordHash string
    SecretNames  []string
}

type Missing2FAFinding struct {
    SecretName string
    Username   string
    URL        string
}

type WatchtowerResult struct {
    TotalSecrets           int
    ExpiringCertificates   int
    PasswordReuseCount     int
    SecretsWithWeakPass    int
    SecretsWithNoOTP       int
    AnalyzedPasswordCount  int
    WeakPasswords          []WeakPasswordFinding
    DuplicatePasswords     []DuplicatePasswordFinding
    Missing2FA             []Missing2FAFinding
}

func Analyze(s store.Store, eng *crypto.Engine, key []byte) (*WatchtowerResult, error)
func AssessPasswordStrength(password string) (PasswordStrength, string)
```

### Requirements

#### Requirement: Strength Scoring

`AssessPasswordStrength` MUST score passwords from VeryWeak to VeryStrong based on length, character diversity, repeated/sequential patterns, and a common-password dictionary.

**Scenario: Common password detected**
- GIVEN password "password123"
- WHEN assessed
- THEN score SHALL be `StrengthVeryWeak` with reason "Common password"

**Scenario: Strong password passes**
- GIVEN a 20-character password with mixed case, digits, and symbols
- WHEN assessed
- THEN score SHALL be `StrengthStrong` or higher with empty reason

#### Requirement: Reuse Detection

`Analyze` MUST group decrypted passwords by SHA-256 hash and flag reuse across secrets.

**Scenario: Reused password found**
- GIVEN two secrets with identical decrypted passwords
- WHEN analyzed
- THEN `result.DuplicatePasswords` SHALL contain one entry with both `SecretNames`

#### Requirement: Missing 2FA Detection

`Analyze` MUST flag password secrets that have a URL but empty `OTPAuth` metadata.

**Scenario: URL without OTPAuth**
- GIVEN a password secret with URL "https://example.com" and no `OTPAuth`
- WHEN analyzed
- THEN `result.Missing2FA` SHALL contain the secret

#### Requirement: Memory Safety

`Analyze` MUST zeroize all decrypted password buffers via `crypto.Zeroize` before returning.

**Scenario: Analysis completes**
- GIVEN a vault with password secrets
- WHEN analysis finishes
- THEN no decrypted plaintext SHALL remain in memory

### Non-Functional Requirements

| Aspect | Requirement |
|--------|-------------|
| Performance | N+1 `GetByName` acceptable for vaults < 1000 secrets |
| Security | All decrypted buffers zeroized; hashes truncated to 16 hex chars for display |
| Error handling | Return error if `store.List()` fails |

### Test Requirements

- Unit tests for `AssessPasswordStrength` covering all five levels and boundary lengths
- Unit tests for reuse detection: 0, 1, and 2+ duplicates
- Unit tests for 2FA detection: with `OTPAuth`, without `OTPAuth`, and missing URL
- Audit test verifying `crypto.Zeroize` is called on decrypted buffers

### Edge Cases

| Case | Behavior |
|------|----------|
| Empty password | Score `VeryWeak` with reason "Empty password" |
| No password secrets | `AnalyzedPasswordCount` = 0; other slices empty |
| Single secret | `DuplicatePasswords` empty |
| Metadata-only `List()` | Fall back to `GetByName` per password secret |

---

## Domain: cli-check

### Requirements

#### Requirement: Metadata Checks Always Run

`vlt check` MUST always run duplicate-name and expiring-certificate checks without unlocking the vault.

**Scenario: Default check**
- GIVEN a locked vault with no issues
- WHEN `vlt check` runs without flags
- THEN it SHALL print "Vault check passed" and exit 0 without password prompt

#### Requirement: Password Analysis Opt-In

`vlt check` MUST accept `--passwords` to enable password security analysis.

**Scenario: Password analysis requested**
- GIVEN a vault with weak passwords
- WHEN `vlt check --passwords` runs
- THEN it SHALL print weak/reuse/2FA findings to stderr after metadata checks

#### Requirement: Vault Unlock

When `--passwords` is set, `vlt check` MUST unlock the vault before analysis.

**Scenario: Locked vault**
- GIVEN a locked vault
- WHEN `vlt check --passwords` runs
- THEN it SHALL prompt for master password, then analyze and print findings

#### Requirement: Backward Compatibility

`vlt check` without `--passwords` MUST produce identical behavior and output as before this change.

**Scenario: Script compatibility**
- GIVEN a CI script running `vlt check`
- WHEN executed
- THEN it SHALL not prompt for password and SHALL produce the same output

#### Requirement: Issue Aggregation

The command MUST count metadata and password findings into a single issue total.

**Scenario: Mixed issues**
- GIVEN duplicate names and weak passwords exist
- WHEN `vlt check --passwords` runs
- THEN the final issue count SHALL include both categories

### Non-Functional Requirements

| Aspect | Requirement |
|--------|-------------|
| Usability | `--passwords` help text MUST state vault unlock is required |
| Performance | Acceptable for typical vaults (< 1000 secrets) |
| Output | Findings to stderr; exit 0 only if zero total issues |

### Test Requirements

- Integration test: `vlt check` without `--passwords` on a locked vault passes
- Integration test: `vlt check --passwords` prompts and prints findings
- Integration test: `vlt check --passwords` with no password secrets prints no password issues
- Regression test: output format matches pre-change expectations

### Edge Cases

| Case | Behavior |
|------|----------|
| Empty vault | "Vault check passed" |
| No password secrets | Metadata checks run; password section silent |
| All passwords strong + no reuse + all 2FA | Password section contributes zero issues |
| `--expiring 0` | Skip certificate check (existing behavior) |
| Unlock cancelled / wrong password | Propagate error and exit non-zero |
