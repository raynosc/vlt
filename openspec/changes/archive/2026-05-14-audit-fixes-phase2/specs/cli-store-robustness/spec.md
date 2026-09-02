# Delta for cli-store-robustness

## ADDED Requirements

### Requirement: Persistent Rate Limiting

The CLI MUST persist failed-attempt state to disk. After 5 failed attempts, the lockout MUST survive process restarts.

#### Scenario: Lockout survives restart

- GIVEN 5 failed attempts triggered a lockout
- WHEN the CLI process restarts
- THEN subsequent attempts SHALL still be rejected until the lockout expires

### Requirement: Package Shadowing Elimination

The codebase MUST not shadow Go standard library package names with local variables.

#### Scenario: Build verification

- GIVEN the project is compiled
- WHEN `go build ./...` runs
- THEN no package shadowing diagnostics SHALL be emitted

### Requirement: Keychain Error Observability

Keychain failures during auto-unlock MUST be logged at error level with a descriptive message.

#### Scenario: Keychain failure logged

- GIVEN the keychain returns an error during auto-unlock
- WHEN the GUI starts
- THEN the error SHALL be logged

### Requirement: Recovery Kit Path Safety

The `vlt init --save-recovery` flag MUST require an explicit file path. If the path is omitted, the command SHALL error.

#### Scenario: Missing path errors

- GIVEN `vlt init --save-recovery` with no path argument
- WHEN the command runs
- THEN it SHALL return an error requiring an explicit path

#### Scenario: Explicit path succeeds

- GIVEN `vlt init --save-recovery /path/to/kit.txt`
- WHEN the command runs
- THEN the recovery kit SHALL be written to the specified path
