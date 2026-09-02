# vault-runtime-hardening Specification

## Purpose

Runtime-time hardening of the vault at rest and of master key material in RAM:
`PRAGMA secure_delete=ON`, `chmod 0600` on vault SQLite files, and `mlock` /
`MADV_DONTDUMP` on master key regions. Reduces exposure from disk forensics, swap
leakage, and core dumps.

## Threat Model

- **Threat A**: Deleted SQLite rows linger in the `vault.sqlite` free-page list;
  `PRAGMA secure_delete=OFF` (default) leaves ciphertext recoverable and, combined with
  future plaintext bugs, could expose fragments. An attacker with a raw block image of
  the DB recovers deleted secrets' ciphertext.
- **Threat B**: `vault.sqlite`, `-wal`, `-shm` are world/group-readable by default on
  some platforms; a local unprivileged user reads the encrypted vault offline.
- **Threat C**: OS swaps the master-key region to disk (`mlock` absent), or a core dump
  captures the key region (`MADV_DONTDUMP` absent). Attacker recovers the master key
  from swap/core and decrypts the whole vault.
- **Mitigations**: `secure_delete=ON` on every connection so deleted ciphertext is
  overwritten; `0600` perms restricted to the owner; `mlock` master-key memory + `MADV_DONTDUMP`
  where available, with graceful per-OS fallback.
- **Residual risk**: Platforms without `mlock` (and without `MADV_DONTDUMP`) fall back
  to a no-op, documented at runtime; tradeoff: feature works everywhere, key protection
  is best-effort on unsupported OSes.

## Requirements

### Requirement: S-10 Secure Delete On Every Connection

The store MUST set `PRAGMA secure_delete=ON` on every connection it opens to
`vault.sqlite`. The setting MUST be applied before any query runs.

#### Scenario: secure_delete enabled on open

- GIVEN a fresh vault
- WHEN any connection is opened to `vault.sqlite`
- THEN `PRAGMA secure_delete` SHALL read ON before any query is executed

#### Scenario: Deleted row overwritten in file

- GIVEN an unlocked vault with a secret stored
- WHEN the secret is deleted
- THEN the freed page content SHALL be overwritten (not just marked free)
- AND a snapshot of `vault.sqlite` SHALL NOT contain the deleted ciphertext page

### Requirement: S-10 Restrictive File Permissions

The store MUST set file mode `0600` on `vault.sqlite`, `vault.sqlite-wal`, and
`vault.sqlite-shm` when they exist. Existing files with broader perms SHALL be tightened
on open; files SHALL NOT be created world/group-readable.

#### Scenario: New vault files created 0600

- GIVEN a fresh vault initialization
- WHEN `Init` creates the SQLite files
- THEN `vault.sqlite`, `-wal`, and `-shm` SHALL have mode `0600`

#### Scenario: Existing loose perms tightened on open

- GIVEN an existing vault whose `vault.sqlite` is mode `0644`
- WHEN the store opens it
- THEN the store SHALL chmod `vault.sqlite` (and `-wal`/`-shm` if present) to `0600`

### Requirement: S-20 Lock Master Key Memory

On darwin and linux, derived master key regions returned by `DeriveKey` /
`VerifyAndDeriveKey` MUST be mlocked (and `MADV_DONTDUMP` set on linux). Where `mlock`
is unavailable or fails, the system SHALL fall back to `MADV_DONTDUMP` alone; where
neither is available the wrapper SHALL degrade to a documented no-op rather than panic.

#### Scenario: mlock applied on darwin

- GIVEN a darwin build of the binary
- WHEN `DeriveKey` returns a master key region
- THEN that region SHALL be mlocked
- AND `MADV_DONTDUMP` MAY be applied as defense-in-depth

#### Scenario: mlock + MADV_DONTDUMP applied on linux

- GIVEN a linux build of the binary
- WHEN `DeriveKey` returns a master key region
- THEN the region SHALL be mlocked AND marked `MADV_DONTDUMP`

#### Scenario: Graceful fallback when mlock unavailable

- GIVEN a platform/build where `mlock` syscall is unavailable
- WHEN `DeriveKey` returns a master key region
- THEN the wrapper SHALL apply `MADV_DONTDUMP` if available
- AND SHALL NOT panic
- AND SHALL return the key region usable for crypto operations

### Requirement: S-20 Daemon Key mlock

The daemon process MUST mlock its persisted daemon key region on load, applying the same
per-OS fallback as the master key path.

#### Scenario: Daemon key locked on linux

- GIVEN a linux daemon process loading `daemon.key`
- WHEN the key is loaded into memory
- THEN the region SHALL be mlocked and `MADV_DONTDUMP`-marked

#### Scenario: Key region released on shutdown

- GIVEN a daemon holding a mlocked key region
- WHEN the daemon shuts down
- THEN the region SHALL be munlocked (or the no-op equivalent) and zeroized