# Proposal: passwd cert-parsing

## Intent

Foundation shipped `Kind` enum with `certificate`/`ssh_key` but zero parsing — everything stores as opaque `other`. Users can't import certs, extract expiry, or filter by type. This change delivers real parsing, auto-detection on file import, and cert-aware CLI.

## Scope

### In Scope
- PEM X.509, PKCS#12, SSH private/public key parsing + metadata extraction
- Schema migration v2: `metadata` JSON column on `secrets`
- `vlt add --file` auto-detects kind; `--password` for PKCS#12
- `vlt inspect` — parse & display metadata without storing
- `vlt list --expiring <Nd>` — certs expiring within N days

### Out of Scope
- Certificate generation, CSR, chain validation, OCSP/CRL
- ACME automation
- Private key encryption/decryption

## Capabilities

### New Capabilities
- `cert-parsing`: All certificate/key format parsing + metadata extraction

### Modified Capabilities
- `cli-commands`: `add --file/--password` flags, `inspect` subcommand, `list --expiring`
- `secret-storage`: schema v2 adds `metadata` column; query by metadata expiry

## Approach

1. **`internal/parse/`** — Pure parsing: PEM X.509 (stdlib), PKCS#12 (go-pkcs12), SSH (`golang.org/x/crypto/ssh`). Extract metadata as typed structs.
2. **Schema v2 migration** — Add `metadata TEXT` JSON column. Store parsed metadata on add.
3. **CLI integration** — `add --file` reads file, auto-detects format, parses, sets kind, stores DER blob + JSON metadata. `inspect` parses & prints only. `list --expiring` queries JSON metadata expiry via SQLite JSON functions.
4. **No crypto dependency** — parsing is decode-only. Keys/certs stored encrypted like any other value.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/parse/` | New | All format parsing + metadata extraction |
| `internal/cli/add.go` | Modified | `--file`, `--password` flags, auto-detect |
| `internal/cli/inspect.go` | New | Read-only parse & display |
| `internal/cli/list.go` | Modified | `--expiring` filter |
| `internal/store/store.go` | Modified | Schema v2, metadata column, ListByExpiry |
| `internal/secret/secret.go` | Modified | CertMetadata, SSHMetadata types |
| `go.mod` | Modified | go-pkcs12, x/crypto/ssh deps |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| go-pkcs12 upstream unmaintained | Low | Pin stable version; error on failure |
| SSH key format edge cases | Med | Table-driven tests with known key fixtures |
| Schema migration on existing vaults | Low | Non-destructive add-column; tested path |

## Rollback Plan

Revert the merge commit. If schema v2 migration ran: `ALTER TABLE secrets DROP COLUMN metadata` (SQLite 3.35+). Test revert before shipping.

## Dependencies

- `golang.org/x/crypto/ssh` — SSH key type detection + fingerprint
- `software.sslmate.com/src/go-pkcs12` — PKCS#12/PFX bundle parsing
- Foundation: `internal/secret/`, `internal/store/`, `internal/cli/`

## Success Criteria

- [ ] PEM X.509 round-trip: parsed metadata matches `openssl x509 -text`
- [ ] SSH key fingerprint matches `ssh-keygen -lf`
- [ ] `vlt add --file cert.pem` sets kind=certificate and stores metadata
- [ ] `vlt inspect cert.pem` displays metadata without storing
- [ ] `vlt list --expiring 30d` returns only certs expiring within 30 days
- [ ] `go test ./...` + `golangci-lint run` + `go vet` all pass
