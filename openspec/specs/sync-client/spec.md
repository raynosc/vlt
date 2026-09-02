# sync-client Specification

## Purpose

Local sync engine that diffs vault state against server state, pushes/pulls encrypted snapshots, merges via last-writer-wins, and logs conflicts — all without exposing plaintext to the network.

## Requirements

### Requirement: Offline-first Operation

The client MUST open and operate on the local vault without any network connectivity.

#### Scenario: Vault opens offline

- GIVEN the device has no network connectivity
- WHEN the user opens the vault
- THEN the vault opens successfully
- AND sync commands report "unavailable" without crashing

### Requirement: Diff Detection

The client MUST compute which secrets were added, modified, or deleted since the last sync by comparing local against the last-synced snapshot.

#### Scenario: Detect pending push

- GIVEN a secret created or modified after the last successful sync
- WHEN `vlt sync status` is invoked
- THEN the output SHALL list the secret as pending push

#### Scenario: Detect pending pull

- GIVEN the server has a newer blob version than the local vault
- WHEN `vlt sync status` is invoked
- THEN the output SHALL report available remote changes

### Requirement: Encrypted Push

The client MUST serialize the full vault (all secrets with metadata) into an encrypted opaque blob and upload it to the server.

#### Scenario: Push succeeds

- GIVEN a vault with pending changes and valid API key
- WHEN the client pushes
- THEN the server SHALL store the blob
- AND the client SHALL update local SyncedAt for all pushed secrets

#### Scenario: Push fails on auth

- GIVEN an invalid API key
- WHEN the client attempts to push
- THEN the client SHALL report authentication failure
- AND SHALL NOT modify local SyncedAt

### Requirement: Encrypted Pull

The client MUST download the latest server blob, decrypt it locally using the master key, and apply changes to the local store.

#### Scenario: Pull applies remote changes

- GIVEN the server has a newer blob
- WHEN the client pulls
- THEN the client SHALL apply remote changes to the local store
- AND update local SyncedAt for affected secrets

#### Scenario: Pull with no changes

- GIVEN local and server are in sync
- WHEN the client pulls
- THEN the client SHALL report no changes

### Requirement: LWW Merge with Conflict Log

The client MUST apply last-writer-wins per secret using the most recent write timestamp,
where a soft-delete (DeletedAt set) is treated as a write event and participates in LWW
ordering. A remote tombstone MUST win over a local live record when its timestamp is newer;
a local tombstone MUST win over a remote live record when its timestamp is newer.
When a local change is overwritten, the previous value SHALL be logged.
(Previously: LWW used SyncedAt only; tombstones did not exist; deleted secrets could
reappear after pull.)

#### Scenario: Tombstone wins over stale live record

- GIVEN a secret was deleted locally at T=100
- AND the server blob contains the same secret as live with UpdatedAt=80
- WHEN the client pulls and merges
- THEN the merged result keeps DeletedAt set
- AND the secret MUST NOT appear in List or GetByName after merge

#### Scenario: Newer live record wins over older tombstone

- GIVEN the server blob contains a secret with UpdatedAt=200
- AND the local store has a tombstone for the same secret with DeletedAt=150
- WHEN the client pulls and merges
- THEN the live record replaces the tombstone
- AND the secret SHALL be visible in List after merge

#### Scenario: Malicious server replay cannot resurrect deleted secret

- GIVEN a secret was deleted at T=100 (tombstone persisted locally)
- AND the server replays a pre-delete blob version where the secret is live with UpdatedAt=50
- WHEN the client pulls and merges
- THEN the tombstone (newer timestamp) SHALL win
- AND the secret MUST NOT reappear in List or GetByName

#### Scenario: Client-side tombstone purge after merge

- GIVEN a tombstone with DeletedAt older than 30 days relative to the current time
- WHEN the client completes a successful merge (post-merge, client-side only)
- THEN the tombstone SHALL be removed from local store
- AND the server blob SHALL NOT be modified as a result of purge

#### Scenario: Tombstone younger than 30 days is retained

- GIVEN a tombstone with DeletedAt=29 days ago
- WHEN the client completes a merge
- THEN the tombstone SHALL remain in local store

#### Scenario: Local edit overwritten (existing scenario — retained)

- GIVEN a local secret with older UpdatedAt than the server version
- WHEN the client pulls
- THEN the server version SHALL replace the local version
- AND the old value SHALL be recorded in the conflict log

### Requirement: Master Key Isolation

The client MUST NOT transmit the master key, any derived key, or any plaintext secret to the server.

#### Scenario: Zero-knowledge push

- GIVEN the client pushes to the server
- THEN the blob SHALL consist solely of opaque ciphertext
- AND the server SHALL be unable to decrypt it

### Requirement: Fresh-Device Anti-Rollback Anchor

On first registration the client MUST persist the vault sequence number returned by the
server (`registration_seq`). On every subsequent pull the client MUST reject any response
where `pullResp.Seq < max(lastSeq, registrationSeq)`. This prevents a compromised server
from serving a stale blob to a fresh device that has no local history to compare against.

#### Scenario: Registration seq persisted

- GIVEN the client calls RegisterVault
- WHEN the server returns a RegisterResponse with VaultSeq=42
- THEN the client SHALL persist registration_seq=42 in local config

#### Scenario: Pull rejected below registration_seq

- GIVEN registration_seq=42 and lastSeq=10
- WHEN the server returns a pull response with Seq=15
- THEN the client SHALL reject the pull with an anti-rollback error
- AND the local vault SHALL NOT be modified

#### Scenario: Pull accepted at max(lastSeq, registrationSeq)

- GIVEN registration_seq=42 and lastSeq=50
- WHEN the server returns a pull response with Seq=50
- THEN the client SHALL accept and apply the pull

#### Scenario: Steady-state re-pull same seq succeeds (regression guard)

- GIVEN the client last pulled at Seq=7 and registration_seq=0
- WHEN the server returns a pull response with Seq=7 and no new changes
- THEN the client SHALL treat this as "no changes" and NOT return an error

### Requirement: Brand-New Vault Pre-Flight Seq Anchor

When registering a brand-new vault (VaultSeq=0 in RegisterResponse), the client MUST
perform a pre-flight GET on the vault status endpoint to anchor the sequence before
accepting the first pull. This prevents a race where the server already has a blob the
client is unaware of.

#### Scenario: Pre-flight anchor on seq=0

- GIVEN the server returns VaultSeq=0 after registration
- WHEN the client performs its first pull
- THEN the client SHALL first GET vault status to retrieve the current server seq
- AND SHALL use that seq as the anti-rollback floor before applying the pull response

#### Scenario: Non-zero VaultSeq skips pre-flight

- GIVEN the server returns VaultSeq=5 after registration (device adding to existing vault)
- WHEN the client performs its first pull
- THEN the client SHALL use VaultSeq=5 as registration_seq directly without a pre-flight GET

### Requirement: Push 409 Auto-Pull Retry

On a CAS conflict (HTTP 409) during push, the client MUST auto-pull to refresh local state
and retry the push exactly once. A second 409 on the retry SHALL surface an error to the
caller. The vault MUST remain readable throughout this process.

#### Scenario: 409 triggers auto-pull and retry succeeds

- GIVEN the server returns 409 on first push attempt
- WHEN the client auto-pulls and retries
- THEN if the retry push succeeds, the operation completes normally

#### Scenario: 409 on retry surfaces error

- GIVEN the server returns 409 on both first push and the retry push
- WHEN the second 409 is received
- THEN the client SHALL return an error to the caller
- AND SHALL NOT attempt a third push

#### Scenario: Vault readable after 409 handling

- GIVEN a push that encountered a 409
- WHEN the error is surfaced (either success or failure path)
- THEN the local vault SHALL remain accessible and consistent
