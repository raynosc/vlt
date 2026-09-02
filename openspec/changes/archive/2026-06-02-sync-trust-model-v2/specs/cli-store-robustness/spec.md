# Delta for cli-store-robustness

## ADDED Requirements

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
