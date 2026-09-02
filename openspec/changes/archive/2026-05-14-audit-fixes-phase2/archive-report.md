# Archive Report: audit-fixes-phase2

**Change**: audit-fixes-phase2
**Archived**: 2026-05-14
**Archived to**: `openspec/changes/archive/2026-05-14-audit-fixes-phase2/`
**Mode**: hybrid

---

## Engram Artifact Observation IDs

| Artifact | Observation ID |
|----------|----------------|
| Proposal | #121 |
| Spec | #123 |
| Design | #122 |
| Tasks | #125 |
| Apply Progress | #128 |
| Verify Report | #130 |

---

## Specs Synced

| Domain | Action | Details |
|--------|--------|---------|
| daemon | Updated | 4 requirements added (panic recovery, progressive lockout, password zeroization, TOCTOU guard) |
| crypto-integrity | Created | 4 requirements added (Argon2 fidelity, OTP PathUnescape, time.Parse propagation, safe OTP URI construction) |
| sync-security | Created | 3 requirements added (TLS enforcement, API key masking, encrypted D-Bus session) |
| cli-store-robustness | Created | 4 requirements added (persistent rate limiting, shadowing elimination, keychain error logging, recovery kit path safety) |
| structural-constants | Created | 3 requirements added (shared version, named exit codes, API route constants) |

---

## Archive Contents

- proposal.md ✅
- specs/ ✅ (5 domain deltas)
- design.md ✅
- tasks.md ✅ (30/30 tasks complete)
- verify-report.md ✅
- archive-report.md ✅

---

## Source of Truth Updated

The following specs now reflect the new behavior:
- `openspec/specs/daemon/spec.md`
- `openspec/specs/crypto-integrity/spec.md`
- `openspec/specs/sync-security/spec.md`
- `openspec/specs/cli-store-robustness/spec.md`
- `openspec/specs/structural-constants/spec.md`

---

## Verify Summary

- **Tasks**: 30/30 complete
- **Test suites**: 15 passing, 0 failures
- **Lint**: 0 new regressions (10 pre-existing issues)
- **Verdict**: PASS WITH WARNINGS

### Resolved Warnings
All 3 verify warnings were addressed during final verification:
1. Version constant unification
2. TUI Argon2 param read-back
3. JSON API key masking

---

## New Packages Introduced

- `internal/version` — shared version constant
- `internal/cli/exitcodes` — shared exit codes
- `internal/cli/lockout` — persistent rate-limit file logic
- `internal/syncserver/routes` — route path constants

---

## SDD Cycle Complete

The change has been fully planned, implemented, verified, and archived.
Ready for the next change.
