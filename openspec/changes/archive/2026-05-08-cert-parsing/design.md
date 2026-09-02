# Design: cert-parsing — Certificate & SSH Key Import with Metadata

## Technical Approach

Three-layer addition: a pure `internal/parse/` package (zero I/O, no project deps), a v2 schema migration adding a JSON `metadata` column, and CLI extensions (`--file`, `--password`, `inspect`, `--expiring`). Flow: CLI reads file bytes → `parse.DetectFormat()` → `parse.Parse*()` → store DER + JSON metadata. Parse layer is stateless; metadata is queryable via SQLite `json_extract()`.

## Architecture Decisions

| Decision | Options | Choice & Rationale |
|----------|---------|-------------------|
| **Metadata struct** | Union struct vs per-format interfaces | **Single union struct** with `omitempty` JSON tags. Stored as opaque JSON blob — consumers read it, they don't polymorphically dispatch. Interface would add ceremony with zero benefit. |
| **Parse API** | Interface vs exported funcs | **Exported functions** (`ParseCertificate`, `ParseSSHPrivateKey`, `ParseSSHPublicKey`, `ParsePKCS12`, `DetectFormat`). No state, no mock needed — callers pass `[]byte`. |
| **Store filter API** | Functional options vs separate methods | **Separate methods** (`ListExpiring(n)`) matching existing pattern (cf. `Search()`). The Store interface is concrete enough that decorator-style options add complexity for no gain. Kind filtering stays client-side (done in `list.go`). |
| **Schema migration** | Auto vs explicit command | **Auto-migrate** on `Init()` — matches existing `runMigrations()` pattern. No user action needed to upgrade v1 vaults. |
| **PKCS12 library** | `go-pkcs12` vs `x/crypto/pkcs12` | `software.sslmate.com/src/go-pkcs12` — maintained fork. `golang.org/x/crypto/pkcs12` is frozen and deprecated since 2021. |
| **File I/O boundary** | CLI vs parse package | **CLI layer** reads files. Parse package takes `[]byte` + optional `string` password — pure function. |

## Data Flow

```
CLI (add --file)
  │
  ├─ os.ReadFile(path) ──→ []byte
  ├─ parse.DetectFormat(bytes) ──→ FormatX509PEM | FormatSSHPrivateKey | ...
  ├─ parse.ParseCertificate(bytes) ──→ *Metadata | error
  │     └─ crypto/x509 ──→ *x509.Certificate
  ├─ DER-encode value ──→ encrypted via crypto.Encrypt()
  ├─ Metadata ──→ json.Marshal() ──→ string
  └─ store.Store(secret{..., Metadata: jsonStr})
       └─ INSERT INTO secrets (..., metadata) VALUES (...)

CLI (list --expiring 30)
  └─ store.ListExpiring(30)
       └─ SELECT ... FROM secrets WHERE json_extract(metadata, '$.not_after')
            BETWEEN date('now') AND date('now', '+30 days')
```

## Package: `internal/parse/`

```go
// Format represents a detected certificate/key format.
type Format int

const (
    FormatUnknown      Format = iota
    FormatX509PEM
    FormatSSHPrivateKey     // PEM with "RSA PRIVATE KEY" or "OPENSSH PRIVATE KEY"
    FormatSSHPublicKey      // "ssh-rsa AAAA..." single-line
    FormatPKCS12            // binary magic bytes 0x30 0x82...
)

// DetectFormat reads magic bytes / PEM headers to identify format.
func DetectFormat(data []byte) Format

// ParseCertificate parses a PEM X.509 cert. Returns nil on non-cert PEM.
func ParseCertificate(pemData []byte) (*Metadata, error)

// ParseSSHPrivateKey parses PEM-encoded SSH private keys (RSA/Ed25519/ECDSA).
func ParseSSHPrivateKey(pemData []byte) (*Metadata, error)

// ParseSSHPublicKey parses an authorized_keys line.
func ParseSSHPublicKey(keyData []byte) (*Metadata, error)

// ParsePKCS12 decrypts and parses a PKCS12/PFX bundle.
// Password must be provided; returns first cert's metadata + bundle info.
func ParsePKCS12(p12Data []byte, password string) (*Metadata, error)
```

### Sentinel Errors

```go
var (
    ErrEmptyInput         = errors.New("empty input")
    ErrInvalidPEM         = errors.New("invalid PEM data")
    ErrWrongPassword      = errors.New("wrong password for PKCS12 bundle")
    ErrUnsupportedKeyType = errors.New("unsupported SSH key type")
)
```

### Metadata Struct

```go
// Metadata holds parsed certificate/key information stored as JSON in the metadata column.
// Fields are format-specific; only relevant fields are populated.
type Metadata struct {
    // Common
    FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`

    // X.509
    SubjectCN         string   `json:"subject_cn,omitempty"`
    IssuerCN          string   `json:"issuer_cn,omitempty"`
    NotBefore         string   `json:"not_before,omitempty"`  // ISO 8601
    NotAfter          string   `json:"not_after,omitempty"`   // ISO 8601 — queryable
    SerialNumber      string   `json:"serial_number,omitempty"`
    FingerprintSHA1   string   `json:"fingerprint_sha1,omitempty"`
    SANs              []string `json:"sans,omitempty"`
    KeyUsage          []string `json:"key_usage,omitempty"`
    ExtKeyUsage       []string `json:"ext_key_usage,omitempty"`
    SignatureAlgorithm string  `json:"signature_algorithm,omitempty"`

    // SSH
    KeyType   string `json:"key_type,omitempty"`   // "ssh-rsa", "ssh-ed25519", etc.
    BitLength int    `json:"bit_length,omitempty"`  // 0 if not applicable
    Comment   string `json:"comment,omitempty"`

    // PKCS12
    CertCount     int      `json:"cert_count,omitempty"`
    FriendlyNames []string `json:"friendly_names,omitempty"`
}
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `internal/parse/parse.go` | Create | DetectFormat + dispatch to format parsers |
| `internal/parse/x509.go` | Create | X.509 PEM → Metadata |
| `internal/parse/ssh.go` | Create | SSH private + public key → Metadata |
| `internal/parse/pkcs12.go` | Create | PKCS12 decryption + Metadata |
| `internal/parse/metadata.go` | Create | Metadata struct + JSON serialization helpers |
| `internal/parse/errors.go` | Create | Sentinel parse errors |
| `internal/parse/parse_test.go` | Create | Table-driven format detection + round-trip tests |
| `internal/parse/testdata/` | Create | Fixture certs, SSH keys, PKCS12 bundles |
| `internal/store/migrations/002_add_metadata.sql` | Create | `ALTER TABLE secrets ADD COLUMN metadata TEXT DEFAULT ''` |
| `internal/store/store.go` | Modify | Schema v2 (CurrentSchemaVersion=2), add migration v2, include metadata in Store/Get/List, add ListExpiring |
| `internal/secret/secret.go` | Modify | Add `Metadata string` field to `Secret` struct |
| `internal/cli/add.go` | Modify | Add `--file`, `--password` flags; auto-detect + parse + store metadata |
| `internal/cli/inspect.go` | Create | Read-only parse & display (no vault, no master pw) |
| `internal/cli/list.go` | Modify | Add `--expiring` flag; extend JSON output with metadata |
| `go.mod` | Modify | Add `software.sslmate.com/src/go-pkcs12` |

## Interfaces / Contracts

**Store interface additions:**

```go
type Store interface {
    // existing methods unchanged...

    // ListExpiring returns secrets whose certificate not_after falls within the
    // next N days. Returns only secrets with metadata (non-null).
    ListExpiring(days int) ([]secret.Secret, error)
}
```

**Secret struct addition:**

```go
type Secret struct {
    // existing fields...
    Metadata string `json:"metadata,omitempty"` // JSON blob from parse package
}
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Parse unit | Each format: valid, invalid, edge cases (expired, SANs, multi-cert) | Table-driven with `testdata/` fixtures. Match metadata against `openssl` / `ssh-keygen` reference output. |
| Parse error | Empty input, bad PEM, wrong password, unsupported key type | Assert specific sentinel errors via `errors.Is()` |
| Store migration | Fresh v2 schema, v1→v2 upgrade, existing data preserved | `t.TempDir()` SQLite files, inspect schema after Init |
| Store ListExpiring | Certs expiring in window, outside window, expired | Seed DB with known dates, query via ListExpiring |
| CLI integration | `add --file`, `inspect`, `list --expiring --json` | Golden file tests for output format |

**Fixtures:** Generate programmatically in a script (committed to `testdata/`):
- Self-signed RSA 2048 cert with SANs (`openssl req -x509`)
- CA-signed chain (leaf + intermediate)
- Expired cert (backdate notBefore/notAfter)
- RSA 2048, Ed25519, ECDSA P-256 SSH private keys (`ssh-keygen`)
- PKCS12 bundle (`openssl pkcs12 -export`)

## Migration / Rollout

No migration required beyond schema auto-migration. Schema v2 adds a nullable column — all existing queries remain compatible. Rollback: revert code + `ALTER TABLE secrets DROP COLUMN metadata` (SQLite 3.37+).

## Open Questions

None.
