# vault-at-rest-hardening Specification

## Purpose

Encryption-at-rest of ALL secret metadata (name, url, username, notes, tags, structured
metadata) plus a clean-break vault schema bump to v7. Ensures `vault.sqlite` contains
ciphertext only — fulfilling the README "ciphertext only" promise broken by S-03.

## Threat Model

- **Threat**: Attacker with read access to `vault.sqlite` (stolen laptop, backup leak,
  forensic snapshot) recovers plaintext secret metadata (names, urls, usernames, notes,
  tags). Even without the master key, names like `github.com` / `bank-login` reveal which
  services the victim uses.
- **Assets**: Secret metadata fields; name-to-secret exact-match lookup for `GetByName`.
- **Attack surface**: The SQLite file at rest; the in-memory decrypted state while the
  vault is unlocked.
- **Mitigations in this spec**: All metadata stored as `crypto.PackEnvelope` ciphertext
  BLOBs; name lookup via HMAC-SHA256(masterKey, "passwd.name."+name) — a DB thief learns
  nothing about names but cannot recover plaintext without the key; locked vault exposes
  no intelligible fields; decrypted metadata only held in RAM (mlocked/zeroized covered
  by `vault-runtime-hardening`).
- **Residual risk**: An attacker who captures the unlocked process memory bypasses
  at-rest encryption — addressed by the runtime-hardening spec, not here.

## Requirements

### Requirement: S-03 Encrypt All Secret Metadata

The store MUST NOT persist any plaintext secret metadata. Name, url, username, notes,
tags, and structured metadata MUST be stored as ciphertext BLOBs produced by
`crypto.PackEnvelope` under the master key. A `name_lookup` column holding
`HMAC-SHA256(masterKey, "passwd.name."+name)` SHALL be persisted as a BLOB with a
UNIQUE constraint to preserve O(1) exact-match `GetByName` without leaking plaintext.

#### Scenario: Fresh vault stores ciphertext metadata only

- GIVEN a fresh vault initialized with `--fresh` and a master password set
- WHEN a secret is created with name `github`, url, username, notes, and tags
- THEN `vault.sqlite` SHALL contain ciphertext BLOBs for every metadata field
- AND the `name_lookup` column SHALL hold the HMAC of `"passwd.name.github"`
- AND a raw `grep` of `vault.sqlite` for `github` SHALL return no match

#### Scenario: GetByName resolves via HMAC lookup

- GIVEN an unlocked vault with a secret named `github`
- WHEN `GetByName("github")` is called
- THEN the store SHALL match the supplied name's HMAC against `name_lookup`
- AND SHALL return the decrypted secret

#### Scenario: Duplicate name rejected via lookup uniqueness

- GIVEN an unlocked vault with a secret named `github`
- WHEN a second secret named `github` is created
- THEN the store SHALL reject the insert via the UNIQUE constraint on `name_lookup`

#### Scenario: Read of a tampered metadata blob fails

- GIVEN an unlocked vault with a secret whose `encrypted_name` BLOB is corrupted
- WHEN the secret is read
- THEN decryption SHALL fail with an integrity error
- AND the store SHALL surface the error without returning partial plaintext

### Requirement: S-03 Locked Vault Exposes No Plaintext

When the vault is locked, the system MUST NOT surface any secret name, url, username,
notes, tags, or metadata in plaintext to any frontend (CLI, TUI, GUI). Listing or
searching REQUIRE an unlocked vault.

#### Scenario: List on locked vault requires unlock

- GIVEN a locked vault
- WHEN any frontend invokes List/Search
- THEN the system SHALL require unlock before returning any secret
- AND SHALL NOT return ciphertext blobs to the frontend

#### Scenario: List on unlocked vault returns decrypted metadata

- GIVEN an unlocked vault with secrets present
- WHEN a frontend invokes List
- THEN the App layer SHALL decrypt metadata in memory
- AND SHALL filter/search in memory over the decrypted fields

### Requirement: S-03 Clean-Break Schema v7

The store SHALL bump `CurrentSchemaVersion` to 7. `Init()` MUST reject opening any v1–v6
vault with an error directing the user to export from the prior build and re-import into a
fresh v7 vault. No in-place migration of v6 vaults is provided.

#### Scenario: Fresh vault creates v7 schema

- GIVEN no existing vault file
- WHEN `Init` is invoked with `--fresh`
- THEN a v7 schema SHALL be created with encrypted-metadata columns
- AND `name_lookup` SHALL exist as a UNIQUE BLOB column

#### Scenario: Legacy v6 vault rejected

- GIVEN a v6 vault file on disk
- WHEN `Init` is invoked without `--fresh`
- THEN the store SHALL reject it with a migration-required error
- AND SHALL NOT modify the existing file

### Requirement: S-03 Search is In-Memory After Full Decrypt

The store interface MUST NOT expose a SQL `Search`. Search, list, list-expiring,
update-metadata, and HOTP-counter-increment SHALL move to the App layer, which decrypts
the full vault into memory, filters, then zeroizes the decrypted buffers.

#### Scenario: Search filters decrypted metadata

- GIVEN an unlocked vault with secrets named `github` and `gitlab`
- WHEN the user searches for the term `git`
- THEN the App layer SHALL decrypt all metadata
- AND SHALL return only secrets whose decrypted fields contain `git`

#### Scenario: Decrypted search buffers zeroized

- GIVEN an unlocked vault where a search just completed
- WHEN the search returns
- THEN decrypted metadata buffers held for the search SHALL be zeroized before reuse/return