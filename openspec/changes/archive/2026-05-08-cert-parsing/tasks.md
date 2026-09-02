# Tasks: passwd cert-parsing

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1080 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1: Tasks 1-3 (parse package, base=`feat/cert-parsing`) → PR 2: Task 4 (schema v2, base=PR 1) → PR 3: Task 5 (CLI, base=PR 2) |
| Delivery strategy | auto-chain |
| Chain strategy | feature-branch-chain |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | `internal/parse/` package (X.509 + SSH + PKCS12 + format detection + Metadata struct + sentinel errors + fixture-based tests) | PR 1 | Base=`feat/cert-parsing`. Pure parse — no store deps. ~580 lines |
| 2 | Schema v2 migration + `ListExpiring()` | PR 2 | Base=PR 1 branch. Depends on Metadata struct from unit 1. ~170 lines |
| 3 | CLI integration (`add --file`, `inspect`, `list --expiring`) | PR 3 | Base=PR 2 branch. Depends on both parse and store. ~330 lines |

## Phase 1: Parse Package

- [x] 1.1 Create `internal/parse/errors.go` — sentinel errors: `ErrEmptyInput`, `ErrInvalidPEM`, `ErrNotX509`, `ErrNotSSH`, `ErrWrongPassword`, `ErrUnsupportedKeyType`
- [x] 1.2 Create `internal/parse/metadata.go` — `Metadata` struct with JSON tags + `IsExpired()` / `DaysUntilExpiry()` helpers
- [x] 1.3 Create `internal/parse/detect.go` — `Format` enum + `Detect()` from PEM headers / SSH pub prefix / PKCS12 magic
- [x] 1.4 Create `internal/parse/x509.go` — `ParseX509()` using `crypto/x509`: PEM/DER, extract all metadata fields
- [x] 1.5 Create `internal/parse/ssh.go` — `ParseSSHPrivate()` + `ParseSSHPublic()` via `golang.org/x/crypto/ssh`
- [x] 1.6 Create `internal/parse/pkcs12.go` — `ParsePKCS12()` using `software.sslmate.com/src/go-pkcs12`
- [x] 1.7 Create `internal/parse/testdata/` — programmatic fixture generation in `parse_test.go`
- [x] 1.8 Write `internal/parse/parse_test.go` — table-driven tests for all parse functions + format detection + error cases + round-trip

## Phase 2: Schema v2 Migration

- [x] 2.1 Create `internal/store/migrations/002_add_metadata.sql` — `ALTER TABLE secrets ADD COLUMN metadata TEXT DEFAULT ''`
- [x] 2.2 Modify `internal/secret/secret.go` — add `Metadata string` field to `Secret` struct
- [x] 2.3 Modify `internal/store/store.go` — bump `CurrentSchemaVersion` to 2, embed migration 002, include `metadata` in Store/Get/List/Search queries, add `ListExpiring(days int)` using `json_extract(metadata, '$.not_after')`
- [x] 2.4 Write store tests — fresh v2 schema, v1→v2 migration preserves data, ListExpiring with window/outside/expired certs

## Phase 3: CLI Integration

- [x] 3.1 Modify `internal/cli/add.go` — add `--file` and `--password` flags, call `parse.Detect()` + correct `Parse*()`, set `kind`, store DER + JSON metadata
- [x] 3.2 Create `internal/cli/inspect.go` — read-only `passwd inspect <file>`, detect format, parse, print metadata to stdout (no vault, no master password)
- [x] 3.3 Modify `internal/cli/list.go` — add `--expiring <Nd>` and `--kind` filter flags; list returns metadata in JSON output
- [x] 3.4 Write CLI integration tests — `add --file` round-trip, `inspect` output, `list --expiring`, `--kind` filter, error messages for bad files

### Implementation Order

Parse → store → CLI. Phase 1 is bottom-up inside the parse package: errors first, then Metadata struct, then detect + format parsers, then fixtures + tests. Phase 2 (schema) depends on Metadata struct definition. Phase 3 (CLI) depends on parse package + store changes.

## Next Step

Ready for implementation (sdd-apply). Three chained PRs in feature-branch-chain: `feat/cert-parsing` as tracker, PR 1 targets tracker, PR 2 targets PR 1 branch, PR 3 targets PR 2 branch.
