# Proposal: Hardening & Breach Alerts

## Intent

Close the CRITICAL security gap (S-03: name/url/username/notes/tags stored plaintext in `vault.sqlite`, contradicting the README "ciphertext only" promise) and add the most visible security feature — local breach detection — so `vlt` is safe to daily-drive. Bundles the remaining hardening backlog (S-10, S-20, U-07, S-18) into one clean-break change.

## Scope

### In Scope
- **S-03** Encrypt ALL secret metadata (name, url, username, notes, tags). Maximum privacy.
- **Clean-break vault schema bump** — fresh vault only, no in-place migration of v6 vaults (user re-imports from backup after hardening lands).
- **S-10** `PRAGMA secure_delete` + `chmod 0600` on `vault.sqlite`, `-wal`, `-shm`.
- **S-20** `mlock` / `MADV_DONTDUMP` for master key material (prevent swap/core dump exposure).
- **U-07** Standalone GUI auto-lock (independent of daemon).
- **S-18** Sync conflict log writes to `sync_conflicts` (currently `config`).
- **Breach alerts** — local bundled breach corpus: download-on-demand, local cache, integrity verification, periodic update; password lookup by SHA-1; integration into `internal/watchtower` so `vlt check` and the GUI Watchtower panel surface hits.

### Out of Scope
- Card / Identity / Bank / Attachments item types
- Browser autofill / browser extension
- Sharing (cross-user), travel mode
- Background automatic sync
- Windows keychain
- HIBP third-party API queries at runtime (local corpus only)
- In-place migration of existing v6 vaults (clean break; user re-imports)

## Capabilities

### New Capabilities
- `vault-at-rest-hardening`: S-03 encrypt-all-secret-metadata + clean-break schema bump.
- `vault-runtime-hardening`: S-10 secure_delete + 0600 perms; S-20 mlock/MADV_DONTDUMP for key material.
- `breach-alerts`: Local breach corpus model + SHA-1 lookup + watchtower surfacing.
- `gui-auto-lock`: U-07 standalone GUI lock-on-idle / lock-on-blur independent of daemon.

### Modified Capabilities
- `sync-client`: S-18 `logConflict` writes to `sync_conflicts` table (not `config`).

## Approach

Sequence the change as: (1) crypto/store layer — schema bump + metadata encryption envelope reuse via `crypto.PackEnvelope`; (2) runtime hardening — DB pragmas, file perms, mlock on master key path; (3) sync S-18 one-line redirect of `logConflict` target; (4) GUI auto-lock timer/menu; (5) breach corpus — downloader, cache on disk, integrity verification (signature/hash), SHA-1 lookup, watchtower panel/CLI wiring. TDD strict (`go test ./...`). Single PR within the 2500-line review budget.

### Open design questions (to be resolved in sdd-design — NOT decided here)
1. **Search after encrypt-all**: with name/url/notes encrypted, how does search/list work? In-memory search after full vault decrypt? Encrypted index? What UX when vault is locked (can item names even be listed)? Biggest design fork.
2. **Breach corpus model**: upstream source, format (SHA-1 sorted list? bloom filter?), integrity scheme (signature/hash), cache location, size, update cadence, opt-in vs default. Corpus is several GB — embedding is not an option.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/store/` | Modified | Schema bump + metadata column encryption (S-03) |
| `internal/crypto/` | Modified | mlock/MADV_DONTDUMP on master key path (S-20) |
| `internal/sync/client.go` | Modified | `logConflict` → `sync_conflicts` (S-18) |
| `internal/gui/` | Modified | Standalone auto-lock (U-07) |
| `internal/watchtower/` | Modified | Breach-hit surfacing |
| `internal/breach/` (new) | New | Corpus downloader, cache, integrity, SHA-1 lookup |
| `internal/cli/check.go` | Modified | Breach hits in `vlt check` output |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| S-03 breaks SQL search → wrong search UX shipped | High | Resolve search design fork in sdd-design before spec |
| Breach corpus model wrong (format/sizing/update/safety) | High | Resolve in sdd-design; prototype download + integrity early |
| 2500-line review budget exceeded | Medium | Sequence hardening tightly; defer nice-to-haves |
| Clean break = user data loss if they forget to re-import | Medium | Document loudly; require explicit `--fresh` flag at init |
| mlock portability (Linux vs macOS) | Medium | Guard per-OS, fall back to MADV_DONTDUMP where mlock unavailable |

## Rollback Plan

Revert the single PR. Existing v6 vaults are unaffected (clean break — no in-place migration was performed), so users on prior builds keep working. Remove `internal/breach/` package and `breach-alerts` / `gui-auto-lock` toggles from frontends. Note: users who created a fresh hardened vault must re-import again from backup.

## Dependencies

- New `internal/breach/` package (stdlib + optional pure-Go HTTP downloader)
- Cross-platform `mlock`/`MADV_DONTDUMP` helpers

## Success Criteria

- [ ] No plaintext secret metadata in `vault.sqlite` (grep on raw file returns nothing for name/url/username/notes/tags)
- [ ] `vault.sqlite`, `-wal`, `-shm` are mode `0600` after init
- [ ] `PRAGMA secure_delete=ON` set on every connection open
- [ ] Master key region is mlocked (or MADV_DONTDUMP fallback applied) on darwin+linux
- [ ] Standalone GUI locks after idle timeout without daemon running
- [ ] Sync conflicts write to `sync_conflicts` (config table no longer contains `conflict:` keys)
- [ ] `vlt check` surfaces breached passwords from the local corpus; GUI Watchtower panel shows breach hits
- [ ] Breach corpus download verifies integrity and refuses a tampered corpus
- [ ] `go test ./...` green; review diff within 2500-line budget