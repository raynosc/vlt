# Delta for sync-client

## Threat Model Addendum

Adversary: malicious or compromised sync server. The server can replay old blobs, serve stale
sequence numbers, or withhold tombstones. Client-side logic MUST enforce correctness
independently of server honesty.

## MODIFIED Requirements

### Requirement: LWW Merge with Conflict Log

The client MUST apply last-writer-wins per secret using the most recent write timestamp,
where a soft-delete (DeletedAt set) is treated as a write event and participates in LWW
ordering. A remote tombstone MUST win over a local live record when its timestamp is newer;
a local tombstone MUST win over a remote live record when its timestamp is newer.
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

## ADDED Requirements

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
