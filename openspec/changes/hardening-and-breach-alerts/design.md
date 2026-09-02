# Design: Hardening & Breach Alerts

## Technical Approach
Bump schema to v7 (clean break), encrypt name/notes/tags/metadata as ciphertext BLOBs using existing `PackEnvelope`, move search and metadata mutation to the `App` layer, add mlock/MADV_DONTDUMP on master key material, redirect sync conflicts to `sync_conflicts`, add standalone GUI idle auto-lock, and integrate a local HIBP breach corpus into watchtower.

## Architecture Decisions

| Decision | Options | Tradeoffs | Choice |
|---|---|---|---|
| Q1 Search after encrypt-all | (a) In-memory decrypt-then-search; (b) Encrypted index table; (c) Deterministic-encrypted index | (a) Simple, reuses existing frontend filtering, RAM exposure mitigated by mlock/zeroize; (b) Complex, leaks index structure; (c) Leaks equality | **(a) In-memory search after full decrypt** |
| Q1 Locked-state UX | Show nothing vs show ciphertext blobs | Names are ciphertext — nothing intelligible to show without the key | **Locked = no names visible; unlock required for all list/search** |
| Q1 Name lookup & uniqueness | App-layer O(n) scan vs HMAC hash column | O(n) breaks `GetByName` performance; HMAC preserves O(1) exact match without leaking plaintext to a DB thief | **HMAC-SHA256(masterKey, "passwd.name."+name) as `name_lookup` BLOB with UNIQUE** |
| Q2 Breach upstream | HIBP Pwned Passwords vs custom corpus | HIBP is CC BY 4.0, comprehensive, well-known; no equally broad open alternative exists | **HIBP Pwned Passwords sorted SHA-1 (assumption: CC BY 4.0 permits local use)** |
| Q2 Corpus format | Sorted text + sparse index vs Bloom filter | Bloom has false positives (unacceptable UX); sorted text + sparse index is exact and memory-light | **Sorted SHA-1 text file with in-memory sparse index (~8.5 MB for 850 M hashes)** |
| Q2 Lookup algorithm | Binary search on mmap vs linear scan | Binary search O(log n) with ~35 disk reads; sparse index reduces to 1-2 block reads | **Binary search with sparse index** |
| Q2 Integrity | Bundled SHA-256 vs fetched SHA-1 | HIBP publishes SHA-1 of archive; we bundle expected SHA-256 of extracted corpus | **SHA-256 of extracted corpus verified on load; archive SHA-1 checked at download** |
| Q2 Cache & trigger | Auto-download vs manual update | Several-GB download must be explicit opt-in per PRD | **Manual `vlt breach update` only; opt-in toggle in settings** |
| Q2 Privacy | Local lookup vs k-anonymity API | PRD mandates local-only | **Local SHA-1 of password, never sent over network** |
| mlock portability | `syscall.Mlock` vs `golang.org/x/sys/unix` | `syscall` is deprecated; `x/sys/unix` is current | **Per-OS build tags in `internal/crypto/mlock_*.go`, graceful no-op fallback** |

## Data Flow

    GUI/TUI/CLI ──→ App.List()/Search() ──→ Store.List() ──→ SQLite
                                          ↓
                                    decrypt metadata in Go
                                          ↓
                                    filter/search in memory
                                          ↓
                                    zeroize decrypted buffers

    Watchtower.Analyze() ──→ decrypt passwords ──→ breach.Lookup(sha1(pw))
                                    ↓
                            append BreachedPasswords to result

## File Changes

| File | Action | Description |
|---|---|---|
| `internal/store/store.go` | Modify | v7 schema; encrypted BLOB columns; `name_lookup` UNIQUE; `secure_delete`; `chmodWAL`; remove `Search`/`ListExpiring`/`UpdateMetadata`/`IncrementHOTPCounter` from interface |
| `internal/secret/secret.go` | Modify | Add `NameLookup`, `EncryptedName`, `EncryptedNotes`, `EncryptedTags`, `EncryptedMetadata` fields |
| `internal/crypto/mlock_*.go` | Create | Per-OS mlock/MADV_DONTDUMP wrappers (darwin `mlock`, linux `mlock+MADV_DONTDUMP`, no-op fallback) |
| `internal/crypto/engine.go` | Modify | Mlock returned keys from `DeriveKey`/`VerifyAndDeriveKey` |
| `internal/gui/app.go` | Modify | Decrypt metadata in `List`/`Search`/`GetByName`; add `ListExpiring`/`UpdateMetadata`/`IncrementHOTPCounter`; new `Count()` on Store for status |
| `internal/gui/autolock.go` | Create | Idle timer (tracks last canvas input) + lock-on-window-hide; default 5 min |
| `internal/gui/watchtower.go` | Modify | Render `BREACHED PASSWORDS` section from `WatchtowerResult.BreachedPasswords` |
| `internal/tui/list.go` | Modify | Decrypt metadata before display/filter; remove direct `Store.ListExpiring` call |
| `internal/tui/search.go` | Modify | Filter on decrypted metadata |
| `internal/cli/check.go` | Modify | Breach output; require unlock for all checks that touch metadata |
| `internal/cli/breach.go` | Create | `vlt breach update` command (download, verify, extract) |
| `internal/sync/client.go` | Modify | `logConflict` → `sync_conflicts` table |
| `internal/daemon/daemon.go` | Modify | Mlock `daemon.key` |
| `internal/watchtower/watchtower.go` | Modify | Breach lookup integration; new `BreachPasswordFinding` |
| `internal/breach/*.go` | Create | Downloader, verifier, sparse index builder, lookup |

## Interfaces / Contracts

```go
// internal/secret/secret.go
 type Secret struct {
     ID                string     `json:"id"`
     NameLookup        []byte     `json:"-"`          // HMAC-SHA256(key, name); DB UNIQUE
     EncryptedName     []byte     `json:"encrypted_name,omitempty"`
     Kind              Kind       `json:"kind"`
     EncryptedValue    []byte     `json:"encrypted_value,omitempty"`
     EncryptedOTPSeed  []byte     `json:"encrypted_otp_seed,omitempty"`
     EncryptedNotes    []byte     `json:"encrypted_notes,omitempty"`
     EncryptedTags     []byte     `json:"encrypted_tags,omitempty"`
     EncryptedMetadata []byte     `json:"encrypted_metadata,omitempty"`
     CreatedAt         time.Time  `json:"created_at"`
     UpdatedAt         time.Time  `json:"updated_at"`
     DeletedAt         *time.Time `json:"deleted_at,omitempty"`
 }

 // internal/breach/corpus.go
 type Corpus struct{}
 func OpenCorpus(dir string) (*Corpus, error)
 func (c *Corpus) Lookup(password string) (bool, error)
 func (c *Corpus) Close() error
```

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit | `mlock_*.go` wrappers, encrypted-metadata `PackEnvelope` round-trip, sparse index binary search | Go test with mock files / small hash sets |
| Integration | `App.List/Search` decrypt-then-filter, `watchtower.Analyze` with mock breach corpus, `Store.Init` v7 creation | In-memory SQLite, inject mock master key |
| E2E | `vlt breach update` flow (stub HTTP server), `vlt check --passwords` breach hit surfacing | Temp dir + test HTTP server |

## Migration / Rollout
Clean break: `CurrentSchemaVersion = 7`. `Init()` rejects existing v1-v6 vaults with an error directing export + re-import. No in-place migration. New vaults get encrypted metadata from creation.

## Open Questions
None — Q1 and Q2 are decided above.
