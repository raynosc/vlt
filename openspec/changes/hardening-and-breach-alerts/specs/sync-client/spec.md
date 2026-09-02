# Delta for sync-client

## MODIFIED Requirements

### Requirement: LWW Merge with Conflict Log

The client MUST apply last-writer-wins per secret using the most recent write timestamp,
where a soft-delete (DeletedAt set) is treated as a write event and participates in LWW
ordering. A remote tombstone MUST win over a local live record when its timestamp is newer;
a local tombstone MUST win over a remote live record when its timestamp is newer.
When a local change is overwritten, the previous value SHALL be logged to the `sync_conflicts`
table (NOT the `config` table). Conflict entries SHALL NOT pollute the `config` table.
(Previously: LWW used SyncedAt only; tombstones did not exist; deleted secrets could
reappear after pull. Conflict log target was the `config` table under `conflict:` keys.)

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

#### Scenario: S-18 Conflict log writes to sync_conflicts table

- GIVEN a local change is overwritten by a remote change during LWW merge
- WHEN the client logs the conflict
- THEN the conflict SHALL be inserted as a row in the `sync_conflicts` table
- AND the `config` table SHALL NOT contain any `conflict:` keys after the merge
- AND a query of `sync_conflicts` SHALL return the recorded conflict entries

#### Scenario: S-18 Pre-existing conflict keys not migrated silently

- GIVEN a vault whose `config` table already contains legacy `conflict:` keys
- WHEN the client performs a merge that produces a new conflict
- THEN the new conflict SHALL be written to `sync_conflicts`
- AND the legacy `config` `conflict:` keys SHALL NOT be consulted as the conflict log
  by the merge logic (legacy data MAY be surfaced separately for cleanup, but reading
  conflicts from `config` is FORBIDDEN)