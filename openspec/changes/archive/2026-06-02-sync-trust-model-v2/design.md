# Technical Design: Sync Trust Model v2

> Status: design (HOW at architecture level). Tasks phase derives the WHAT-to-do steps.
> Proposal: `openspec/changes/sync-trust-model-v2/proposal.md`.
> STRICT TDD active (`go test ./...`). All new tests pure-Go, no CGO.

## 1. Architecture Overview

No new packages, no new layering. This change hardens four existing seams inside the
already-layered design:

```
secret (domain)        <- H2: DeletedAt field on Secret
   ^
store (SQLite blob)    <- H2: schema v6 deleted_at + SoftDelete + filtered reads + purge SQL
   ^
sync.Client            <- H2 merge/purge, F1/F2 effectiveSeq + pre-flight, F3 version gate, F4 retry
   ^
sync types (wire)      <- F1/F2 RegisterResponse.VaultSeq, F3 config_format_version constants
   ^
cli/sync.go, gui       <- H2 SoftDelete call-site, F1/F2 registration_seq write, F3 version write
   ^
syncserver             <- F1/F2 surface VaultSeq in RegisterResponse / pre-flight Seq read
```

The server stays a dumb opaque-blob store. Every trust decision is client-side. The only
server-visible change is echoing the current `seq` back at registration time (F1/F2) — it
already exposes `seq` via `GET /pull` and `GET /status`, so this leaks nothing new.

## 2. ADR-style Decisions

### ADR-1 — Tombstone representation: `DeletedAt *time.Time` (Option A)

**Decision.** Add to `secret.Secret`:

```go
DeletedAt *time.Time `json:"deleted_at,omitempty"`
```

Pointer, not zero-value sentinel. Rationale:
- `omitempty` on a `*time.Time` omits the field entirely when nil — a pre-v6 client never
  sees `deleted_at` in the JSON payload and round-trips cleanly (backward-compat rides on this).
- A zero-value `time.Time` is NOT omitted by `omitempty` (it is a struct, always non-empty in
  Go's encoding/json), so a sentinel would leak `"deleted_at":"0001-01-01T00:00:00Z"` into every
  payload and break old-client compat. Pointer is the only correct choice.
- A live secret has `DeletedAt == nil`. A tombstone has `DeletedAt != nil` and the value is the
  deletion instant (UTC).

**Rejected alternative.** Separate `tombstones` table / boolean `deleted` column. Rejected: a
boolean loses the deletion timestamp needed for LWW comparison and the 30-day purge horizon, and
a separate table complicates the single-snapshot push model (the whole vault is one JSON payload).

### ADR-2 — LWW comparison key = `effectiveTS(s) = max(UpdatedAt, DeletedAt)`

**Decision.** Define a single comparison key used everywhere a "which write is newer" decision is made:

```go
// effectiveTS returns the timestamp that represents the most recent write to a
// secret, treating a tombstone deletion as a write.
func effectiveTS(s secret.Secret) time.Time {
    if s.DeletedAt != nil && s.DeletedAt.After(s.UpdatedAt) {
        return *s.DeletedAt
    }
    return s.UpdatedAt
}
```

`mergeSecrets` compares `effectiveTS(remote)` vs `effectiveTS(local)`. A tombstone with a
`DeletedAt` later than the live copy's `UpdatedAt` WINS — this is what stops forced resurrection:
a malicious server replaying the pre-delete blob carries the old `UpdatedAt`, which loses to the
tombstone's later `DeletedAt`.

**Tie-break (pinned).** When `effectiveTS(remote) == effectiveTS(local)` exactly:
1. **Tombstone beats live** — if exactly one side is a tombstone, the tombstone wins. (Deletion is
   "stickier" than a same-instant edit; prevents resurrection on a clock collision.)
2. If both are tombstones, or both are live, **local wins** (preserves the existing
   "prefer local on tie" rule — `remoteSec.UpdatedAt.After(localSec.UpdatedAt)` was strict `After`).

So the merge winner predicate becomes:
```
remoteWins := effectiveTS(remote).After(effectiveTS(local))
           || (effectiveTS(remote).Equal(effectiveTS(local)) && isTomb(remote) && !isTomb(local))
```

### ADR-3 — `mergeSecrets` returns tombstones; Pull applies them as SoftDelete

**Decision.** `mergeSecrets` keeps tombstones in its output (it does NOT drop deleted entries).
The Pull apply-loop, after picking the winner, branches on `winner.DeletedAt`:

- winner is a tombstone AND local copy is live  → `store.SoftDelete(name)` (writes `deleted_at`,
  clears `encrypted_value`/`encrypted_otp_seed` is NOT required — keep row, just mark; see ADR-4).
- winner is a tombstone AND no local row         → insert a tombstone row (so the deletion
  propagates further and survives a later replay) via `store.Store` with `DeletedAt` set.
- winner is live AND newer than local            → existing replace path (Delete-then-Store), but
  this is an internal replace, NOT a user deletion — see ADR-5 on call-site separation.

The current apply-loop's `sec.UpdatedAt.After(localSec.UpdatedAt)` comparison is replaced by the
`effectiveTS`-based predicate so it agrees with `mergeSecrets`.

### ADR-4 — Schema v6: `deleted_at TEXT DEFAULT NULL`; reads filter; SoftDelete signature

**Decision.** Bump `CurrentSchemaVersion` to **6** (see §3 for the cert-parsing coordination).

```sql
-- migration006
ALTER TABLE secrets ADD COLUMN deleted_at TEXT DEFAULT NULL;
```

Additive, nullable, no data migration — a v5 binary reading a v6 DB ignores the column harmlessly
(rollback-safe, matches the proposal's rollback plan). Stored as RFC3339 TEXT to match
`created_at`/`updated_at` formatting already in `Store`.

**Reads filter deleted rows by default.** `List`, `Search`, `GetByName`, `GetByID`, `ListExpiring`
all add `WHERE deleted_at IS NULL` so the UI/CLI never shows a tombstone. The internal sync path
needs the tombstones, so add a dedicated method that does NOT filter:

```go
// ListWithTombstones returns all secrets including soft-deleted ones, with
// full encrypted values. Used only by the sync layer for snapshot push/merge.
func (s *SQLStore) ListWithTombstones() ([]secret.Secret, error)
```

`getBy` and `scanMetadata` gain a nullable `deleted_at` scan (`sql.NullString` → `*time.Time`).
When non-null, parse RFC3339 into `sec.DeletedAt`.

**SoftDelete signature:**
```go
// SoftDelete marks a secret as deleted by stamping deleted_at = now (UTC).
// The row is retained so the tombstone can propagate via sync. Returns
// ErrNotFound if the name does not exist or is already deleted.
func (s *SQLStore) SoftDelete(name string) error
// UPDATE secrets SET deleted_at = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL
```

`SoftDelete` is added to the `Store` interface alongside `Delete`. `Delete` (hard delete) stays —
it is still needed for the internal Delete-then-Store replace and for the purge.

### ADR-5 — Call-site separation: user deletion = SoftDelete; replace/purge = hard Delete

This is the load-bearing distinction the grep surfaced. `store.Delete` is currently used for TWO
semantically different things:

| Call site | Current | New | Reason |
|-----------|---------|-----|--------|
| `cli/rm.go:66` | `Delete` | **`SoftDelete`** | genuine user deletion → must tombstone |
| `gui/app.go:369,425,478,902`, `gui.go:1813`, `tui/list.go:446` | `Delete` | **`SoftDelete`** | genuine user deletion |
| `cli/add.go:107,244` (re-store on overwrite) | `Delete` | **unchanged hard `Delete`** | replace, not deletion |
| `cli/edit.go:144` (delete-then-store edit) | `Delete` | **unchanged hard `Delete`** | replace, not deletion |
| `cli/import.go:156,398` | `Delete` | **unchanged hard `Delete`** | overwrite-on-import is a replace |
| `tui/add.go:216` (edit re-store) | `Delete` | **unchanged hard `Delete`** | replace |
| `sync/client.go:327` (merge replace) | `Delete` | **unchanged hard `Delete`** | internal merge replace |

Only the user-facing "delete this secret" intent becomes `SoftDelete`. Replace flows stay hard
`Delete` so they don't accidentally create tombstones for an item the user is actively editing.
The tasks phase MUST audit each call site against this table — do not blanket-rename.

### ADR-6 — 30-day purge: client-side, post-merge only, in Pull

**Decision.** Purge runs **only** at the end of `Client.Pull()`, after the merge+apply loop and
after `last_sync_seq` is saved. Never on the server, never on Push.

```go
const tombstonePurgeHorizon = 30 * 24 * time.Hour

// purgeExpiredTombstones hard-deletes tombstones older than the horizon.
func (c *Client) purgeExpiredTombstones() error
// DELETE FROM secrets WHERE deleted_at IS NOT NULL AND deleted_at < <now-30d RFC3339>
```

A new store method `PurgeTombstones(before time.Time) (int, error)` does the SQL; `Pull` computes
`time.Now().UTC().Add(-tombstonePurgeHorizon)` and calls it. Post-merge ordering matters: we must
let an incoming tombstone land and propagate at least once before it is eligible for purge, and the
horizon guarantees every honest peer has had 30 days to observe it. Purging on Push would risk
dropping a tombstone the local device created seconds ago before any peer saw it.

**Old-client compat (pinned).** A pre-v6 client receiving a payload that contains
`"deleted_at"` simply has no field to unmarshal it into — Go drops unknown JSON keys. It resurrects
the secret locally (it never learned about the deletion). On the next pull AFTER that client
upgrades to v6, the tombstone (still present in the snapshot, within the 30-day window) wins by
LWW and the secret disappears again. This is the "self-healing on upgrade" property. Within the
window the snapshot always carries live tombstones, so no permanent resurrection.

### ADR-7 — Push must include tombstones in the snapshot

`Push` currently builds `fullSecrets` from `List()` (which will now filter tombstones). Change
`Push` to use `ListWithTombstones()` so deletions propagate. Without this, a soft-deleted secret
would never reach the server and peers would never learn of the deletion.

### ADR-8 — F1/F2 `registration_seq` anti-rollback anchor

**Storage.** New config key `registration_seq` (string-encoded int64, same convention as
`last_sync_seq`). Written during `vlt sync init` (cli/sync.go) from `RegisterResponse.VaultSeq`.

**Wire change.** `RegisterResponse` gains:
```go
VaultSeq int64 `json:"vault_seq"`
```
`handler.go handleRegister` sets `resp.VaultSeq`. For a fresh `CreateVault` the seq is 0; if the
vault already existed (re-register / adopt-existing), the handler reads the current seq via
`GetVault`/`GetVaultStatus` and returns it. This is the "fresh-device anchor": when device B adopts
an existing vault, it records the server's real seq at adoption time instead of trusting a later
pull's seq.

**Pull check.** In `Pull`, replace the bare `lastSeq` with:
```go
registrationSeq := readConfigInt("registration_seq") // 0 if unset
effectiveSeq := max(lastSeq, registrationSeq)
if pullResp.Seq < effectiveSeq {
    return nil, fmt.Errorf("rollback detected: server seq %d < effective seq %d", pullResp.Seq, effectiveSeq)
}
```
This rejects a server that serves a blob older than what the device anchored at registration.

**Fresh-vault pre-flight (seq=0) — infinite-loop avoidance.** A brand-new vault has
`registration_seq == 0` and `last_sync_seq == 0`, so `effectiveSeq == 0` and any served seq passes.
That is the gap F1/F2 closes. Pre-flight: when `effectiveSeq == 0`, before accepting the pull body,
issue a `GET /status` (metadata only, no blob) to read the server's claimed current seq, and:
- anchor `registration_seq = statusSeq` (persist it) BEFORE decrypting/accepting the pull;
- then require `pullResp.Seq >= statusSeq`.

**Loop avoidance is structural, not retry-based:** the pre-flight is a single `GET /status` call
guarded by `if effectiveSeq == 0`. After it runs once it writes a non-zero `registration_seq`
(when status seq > 0), so a subsequent Pull no longer enters the pre-flight branch. There is NO
loop — pre-flight calls `Status`, not `Pull`, and `Status` does not recurse. If status seq is still
0 (truly empty vault) the pre-flight is a no-op and the normal monotonic check (≥0) applies; the
first real push will move seq to 1 and anchor future pulls. We do not retry pre-flight.

### ADR-9 — F3 `config_format_version` nil-AAD gate

**Storage.** New config key `config_format_version`, string-encoded int. Values:
- `1` = legacy (nil-AAD fallback permitted) — the implicit state when the key is absent.
- `2` = key-name-AAD only (nil-AAD fallback DISABLED).

**Signature change.** `UnwrapConfigValue` gains a `configVersion int` parameter:
```go
func UnwrapConfigValue(keyName string, stored, masterKey []byte, configVersion int) (plaintext []byte, wrapped bool, err error)
```
When `configVersion >= 2`, the function does NOT attempt the nil-AAD fallback (lines 58-63 of
current secrets.go are skipped); it returns the AAD-decrypt error directly. This prevents a
malicious server-influenced or tampered legacy blob from silently downgrading a migrated vault to
nil-AAD decryption.

**Call sites updated** (both read the key first; absent → 1):
- `internal/sync/client.go:45,54` — `newClientInternal` reads `config_format_version` once and
  passes it into both `UnwrapConfigValue` calls.
- `internal/cli/sync.go:400` — `runSyncShowAPIKey` (the `vlt sync ...` command) reads the key and
  passes it.
- Existing tests in `internal/sync/secrets_test.go` (5 call sites) get the new `configVersion`
  arg — pass `1` to preserve current legacy-fallback behavior they assert.

**Write point (atomic invariant).** In `newClientInternal`, AFTER both lazy re-wraps succeed (the
two `if !apiWrapped` / `if !syncWrapped` blocks at lines 61-72), and ONLY if both `ConfigSet` calls
returned no error, write `config_format_version = 2`. Concretely:
```go
apiOK := apiWrapped
if !apiWrapped { /* rewrap; apiOK = (ConfigSet err == nil) */ }
syncOK := syncWrapped
if !syncWrapped { /* rewrap; syncOK = (ConfigSet err == nil) */ }
if apiOK && syncOK {
    _ = s.ConfigSet("config_format_version", []byte("2"))
}
```
If either re-wrap fails to persist, the version stays at 1 and the fallback remains available next
run — no half-migrated vault gets locked out. The current code ignores the `ConfigSet` error
(`_ = s.ConfigSet(...)`); we must capture it to gate the version write.

Also write `config_format_version = 2` at fresh `vlt sync init` time (cli/sync.go), since a
freshly-initialized vault is born in the new format — both values are wrapped with key-name AAD
from the start.

### ADR-10 — F4 Push 409 auto-pull retry (loop bound = 1)

**Decision.** Refactor the body of `Push` into an unexported `pushOnce() (int64, error)` that
returns a sentinel on CAS conflict:
```go
var errSeqConflict = errors.New("sequence conflict")
```
`pushOnce` returns `errSeqConflict` when the server responds 409. `Push` becomes:
```go
func (c *Client) Push() (int64, error) {
    seq, err := c.pushOnce()
    if !errors.Is(err, errSeqConflict) {
        return seq, err            // success or non-conflict error
    }
    // one auto-pull to absorb the remote change, then retry exactly once
    if _, perr := c.Pull(); perr != nil {
        return 0, fmt.Errorf("push conflict, auto-pull failed: %w", perr)
    }
    seq, err = c.pushOnce()
    if errors.Is(err, errSeqConflict) {
        return 0, fmt.Errorf("sequence conflict after auto-pull retry: pull and try again")
    }
    return seq, err
}
```
Loop bound is literally one retry (no `for`). On a second 409 the error surfaces to the caller —
no further auto-pull, no recursion. This is a UX lost-update fix, not security; the AAD/CAS
invariant already guarantees the vault stays readable.

## 3. Migration Ordering vs cert-parsing (coordination plan)

Both this change and `cert-parsing` touch the shared `store.go` schema (`CurrentSchemaVersion`,
`migrationForVersion`) and possibly `secret.Secret`. Schema versions are a linear sequence — two
changes cannot both claim "v6".

**Recommendation:** this change claims **v6 = `deleted_at`** and proceeds on the assumption it
lands first (it is security-priority H2). Concrete coordination:

1. **Prerequisite check before apply** (per proposal Risks row): inspect `cert-parsing` state. If
   `cert-parsing` has NOT yet bumped the schema → take v6 here unconditionally.
2. **If `cert-parsing` already merged a v6** → this change rebases to **v7**: add
   `migration007` for `deleted_at`, bump `CurrentSchemaVersion = 7`, add `case 7:` to
   `migrationForVersion`. The migration SQL is version-number-agnostic; only the constant and the
   switch case move.
3. Both changes add COLUMNS (additive `ALTER TABLE secrets ADD COLUMN`), so there is no SQL-level
   conflict — only the version-number bookkeeping needs to be linear. Whoever lands second rebases
   the constant + switch case.
4. `secret.Secret` field additions (`DeletedAt` here, cert fields there) are independent struct
   fields — they merge cleanly; only `json` tag collisions would conflict, and `deleted_at` is
   unique.

Record the chosen version number in the tasks artifact so `sdd-apply` does not guess.

## 4. Test Strategy (STRICT TDD — RED first, pure-Go)

All tests are pure-Go (modernc.org/sqlite, net/http/httptest). RED tests to author before any
production change, per item:

**H2 Tombstones**
- `store_test.go`: `SoftDelete` marks `deleted_at`; `List`/`GetByName`/`Search` exclude it;
  `ListWithTombstones` includes it; `SoftDelete` on missing/already-deleted → `ErrNotFound`;
  `PurgeTombstones(before)` deletes only rows older than `before` and returns the count.
- `client_test.go` (merge, table-driven on `mergeSecrets`):
  - remote tombstone (DeletedAt > local UpdatedAt) wins → secret removed locally.
  - replayed pre-delete remote blob (old UpdatedAt) loses to local tombstone → stays deleted (the
    core anti-resurrection assertion).
  - tie at equal effectiveTS: tombstone beats live; both-tombstone → local wins.
  - tombstone present only remotely, no local row → inserted as tombstone.
- `client_test.go` (purge): `Pull` purges tombstones older than 30d post-merge; a 29-day tombstone
  survives; purge never runs on `Push`.
- Old-client compat: marshal a payload WITH `deleted_at`, unmarshal into a struct WITHOUT the field
  (simulate via raw map) → no error; round-trip a v6 Secret with nil DeletedAt → no `deleted_at`
  key in JSON (assert `omitempty`).

**F1/F2 registration_seq**
- `handler_test.go`: register a brand-new vault → `RegisterResponse.VaultSeq == 0`; register/adopt
  an existing vault at seq N → `VaultSeq == N`.
- `client_test.go`: `Pull` with `registration_seq=5`, server serves seq 3 → rollback error
  (`effectiveSeq` uses the max). Fresh vault (effectiveSeq 0): pre-flight `GET /status` returns
  seq 4, then `/pull` returns seq 2 → rejected; pre-flight runs exactly once (httptest counts
  `/status` hits == 1, no loop).

**F3 config_format_version**
- `secrets_test.go`: `UnwrapConfigValue(..., configVersion=2)` on a nil-AAD legacy blob → error
  (no fallback). With `configVersion=1` → fallback succeeds + `wrapped=false` (existing behavior
  preserved). Existing 5 call sites updated with explicit `1`.
- `client_test.go`: after `newClientInternal` lazily re-wraps both values, `config_format_version`
  reads `2`. If a forced `ConfigSet` failure is injected on one re-wrap, version stays `1`.

**F4 409 retry**
- `client_test.go` with httptest: server returns 409 once then 200 → `Push` succeeds after one
  auto-pull (assert `/pull` hit exactly once, `/push` hit twice). Server returns 409 twice →
  `Push` returns the "after auto-pull retry" error and stops (no third push).

## 5. Backward-Incompatibility Surface

| Surface | Incompat? | Handling |
|---------|-----------|----------|
| `secret.Secret` new `DeletedAt *time.Time` omitempty | No (wire) | omitempty → invisible to pre-v6 peers |
| Schema v6 `deleted_at` | No | additive nullable; v5 binary ignores it |
| `UnwrapConfigValue` signature (+`configVersion`) | **Yes (Go API)** | internal package; update all 7 call sites (2 prod + 5 tests) in same change |
| `Store` interface (+`SoftDelete`, +`ListWithTombstones`, +`PurgeTombstones`) | **Yes (Go API)** | internal; `SQLStore` is the only impl; update mocks/tests |
| `RegisterResponse` (+`VaultSeq`) | No (wire) | new field; old clients ignore it; server fills it |
| `config_format_version=2` | No | absent ⇒ treated as 1; rollback leaves vault at 1 |
| Push now sends tombstones in payload | No | old clients drop unknown `deleted_at`, resurrect locally, self-heal on upgrade |

## 6. Risks / Unresolved

- **R1 (Med):** cert-parsing schema-version collision — mitigated by §3 rebase plan; the exact
  version number (6 vs 7) is decided at apply time against repo state.
- **R2 (Low):** purge-before-propagation if a device is offline > 30 days — accepted; 30d is the
  agreed honest-peer observation window. A device offline longer may resurrect, healed on its next
  full pull only if the tombstone still exists somewhere within window. This is an inherent
  CRDT-tombstone-GC tradeoff, not a new bug.
- **R3 (Low):** the `Store` interface grows three methods — any external fake implementing `Store`
  breaks compile. Confirmed single impl (`SQLStore`) + tests; acceptable.
- **R4 (assumption to validate):** `GET /status` is authenticated and returns the live seq for the
  pre-flight; confirmed by `handleStatus` + `GetVaultStatus` reading `COALESCE(seq,0)`.

## 7. Delivery (from proposal, unchanged)

PR1 = H2 + F1/F2 (~380 lines, budget edge — stack H2 and F1/F2 separately if RED tests push >400).
PR2 = F3 + F4. Schema migration additive; rollback per PR.
