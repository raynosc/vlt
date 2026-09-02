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

### Requirement: Schema v6 with Soft-Delete Support

The local SQLite store MUST support schema version 6, adding a nullable `deleted_at`
column to the secrets table. `List` and `GetByName` MUST filter out records where
`deleted_at IS NOT NULL`. A `SoftDelete(name)` method MUST set `deleted_at` to the
current UTC time without removing the row.

#### Scenario: Soft-deleted secret absent from List

- GIVEN a secret that has been soft-deleted (deleted_at set)
- WHEN List is called
- THEN the deleted secret SHALL NOT appear in the returned slice

#### Scenario: Soft-deleted secret absent from GetByName

- GIVEN a secret that has been soft-deleted
- WHEN GetByName is called with that secret's name
- THEN it SHALL return not-found (or equivalent zero value) rather than the deleted record

#### Scenario: SoftDelete sets deleted_at without removing row

- GIVEN an existing secret in the store
- WHEN SoftDelete is called with its name
- THEN the row SHALL remain in the database
- AND deleted_at SHALL be set to a non-null UTC timestamp

#### Scenario: Schema migration from v5 to v6 is additive

- GIVEN a database at schema v5 (no deleted_at column)
- WHEN the store opens and runs migrations
- THEN the secrets table SHALL gain a deleted_at column with DEFAULT NULL
- AND all existing rows SHALL have deleted_at=NULL (not affected)

#### Scenario: SoftDelete on non-existent secret

- GIVEN a name that does not exist in the store
- WHEN SoftDelete is called with that name
- THEN it SHALL return an error indicating the record was not found
