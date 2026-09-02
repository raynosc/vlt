# Delta Specs: cert-parsing

## cert-parsing (NEW CAPABILITY)

### R-001: Parse PEM X.509 Certificate

**Capability**: cert-parsing
**Priority**: P0

The system MUST parse PEM-encoded X.509 certificates and extract: SubjectCN, IssuerCN, NotBefore, NotAfter, SHA-256 hex fingerprint, SerialNumber, SANs (DNS/IP), KeyUsage, and ExtKeyUsage.

#### Scenario: Parse valid PEM certificate

- **Given** a valid PEM-encoded X.509 certificate with known fields
- **When** `ParseCertificate(pemData)` is called
- **Then** all metadata fields are returned matching `openssl x509 -text` output

#### Scenario: Certificate with multiple SANs

- **Given** a certificate with 5 DNS Subject Alternative Names
- **When** parsed
- **Then** all 5 SANs are returned in the SANs slice

#### Scenario: Self-signed certificate

- **Given** a self-signed certificate where Subject == Issuer
- **When** parsed
- **Then** SubjectCN and IssuerCN are identical

### R-002: Parse SSH Private Key

**Capability**: cert-parsing
**Priority**: P0

The system MUST parse PEM-encoded SSH private keys (RSA, Ed25519, ECDSA) and extract key type, bit length, SHA-256 fingerprint, and comment.

#### Scenario: Parse RSA private key

- **Given** a PEM-encoded RSA 2048-bit private key
- **When** `ParseSSHPrivateKey(pemData)` is called
- **Then** key type is "ssh-rsa", bit length is 2048, fingerprint matches `ssh-keygen -lf`

#### Scenario: Parse Ed25519 private key

- **Given** a PEM-encoded Ed25519 private key
- **When** parsed
- **Then** key type is "ssh-ed25519", bit length is 256

#### Scenario: Parse ECDSA P-256 private key

- **Given** a PEM-encoded ECDSA P-256 private key
- **When** parsed
- **Then** key type is "ecdsa-sha2-nistp256", bit length is 256

#### Scenario: Unsupported key type

- **Given** a DSA private key
- **When** parsed
- **Then** an `ErrUnsupportedKeyType` error is returned with a descriptive message

### R-003: Parse SSH Public Key

**Capability**: cert-parsing
**Priority**: P0

The system MUST parse SSH `authorized_keys` format public keys and extract key type, SHA-256 fingerprint, and comment.

#### Scenario: Parse RSA public key with comment

- **Given** an SSH public key line with type, base64 data, and "user@host" comment
- **When** `ParseSSHPublicKey(keyData)` is called
- **Then** key type is "ssh-rsa", fingerprint matches reference, comment is "user@host"

#### Scenario: Public key with no comment

- **Given** a public key line with only type and base64 data
- **When** parsed
- **Then** comment is empty string (not an error)

### R-004: Parse PKCS#12 Bundle

**Capability**: cert-parsing
**Priority**: P1

The system MUST decrypt PKCS#12/PFX bundles with a password and return certificate count and friendly names.

#### Scenario: Parse bundle with correct password

- **Given** a PKCS#12 bundle containing 2 certificates (CA + leaf) with friendly names
- **When** `ParsePKCS12(p12Data, password)` is called
- **Then** certificate count is 2 and friendly names match embedded values

#### Scenario: Wrong password

- **Given** a valid PKCS#12 bundle
- **When** parsed with incorrect password
- **Then** an `ErrWrongPassword` error is returned

#### Scenario: Corrupted PKCS#12 data

- **Given** truncated or malformed PKCS#12 bytes
- **When** parsed
- **Then** a parse error with "corrupted PKCS#12 data" message is returned

### R-005: Format Auto-detection

**Capability**: cert-parsing
**Priority**: P0

The system MUST detect certificate/key format from content alone via `DetectFormat(data)`.

#### Scenario: Detect PEM X.509 certificate

- **Given** data starting with `-----BEGIN CERTIFICATE-----`
- **When** `DetectFormat(data)` is called
- **Then** format is `FormatX509PEM`

#### Scenario: Detect SSH private key

- **Given** data starting with `-----BEGIN OPENSSH PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`
- **When** `DetectFormat(data)` is called
- **Then** format is `FormatSSHPrivateKey`

#### Scenario: Detect SSH public key

- **Given** a single line starting with `ssh-rsa AAAA...` or `ssh-ed25519 AAAA...`
- **When** `DetectFormat(data)` is called
- **Then** format is `FormatSSHPublicKey`

#### Scenario: Detect PKCS#12

- **Given** binary data with PKCS#12 magic bytes
- **When** `DetectFormat(data)` is called
- **Then** format is `FormatPKCS12`

#### Scenario: Unknown format returns unknown

- **Given** arbitrary text or binary data
- **When** `DetectFormat(data)` is called
- **Then** format is `FormatUnknown`

### R-006: Parse Error Handling

**Capability**: cert-parsing
**Priority**: P1

Parse errors MUST return descriptive messages, not raw Go errors. All sentinel errors MUST be exported for callers to match.

#### Scenario: Invalid PEM data

- **Given** data with missing PEM header/footer
- **When** any parse function is called
- **Then** an `ErrInvalidPEM` error with "invalid PEM data: <reason>" is returned

#### Scenario: Empty input

- **Given** zero-length input
- **When** any parse function is called
- **Then** an `ErrEmptyInput` error is returned

---

## cli-commands (MODIFIED)

Delta against `openspec/specs/cli-commands/spec.md`.

### MODIFIED REQUIREMENTS

#### MODIFIED: passwd add

(Previously: encrypt and store a new secret with prompted or inline value)

The system MUST encrypt and store a new secret. When `--file <path>` is provided, the system MUST auto-detect the format, parse metadata, set `kind`, encrypt the DER-encoded value, and store metadata in the `metadata` column. PKCS#12 files require `--password`.

#### Scenario: Add certificate from file

- **Given** an initialized vault and a valid PEM cert file
- **When** `passwd add mycert --file cert.pem` runs
- **Then** format is auto-detected as X.509, kind is `certificate`, metadata is stored in the `metadata` column, DER value is encrypted

#### Scenario: Add SSH key from file

- **Given** an initialized vault and a valid RSA private key file
- **When** `passwd add mykey --file id_rsa` runs
- **Then** kind is `ssh_key`, SSH metadata (type, bit length, fingerprint) is stored

#### Scenario: Add PKCS#12 with password

- **Given** an initialized vault and a PKCS#12 bundle
- **When** `passwd add mybundle --file bundle.p12 --password p12pass` runs
- **Then** the bundle is decrypted, first certificate is stored with kind `certificate`, metadata includes friendly name

#### Scenario: Non-existent file returns error

- **Given** an initialized vault
- **When** `passwd add mycert --file nonexistent.pem` runs
- **Then** "Error: file not found: nonexistent.pem" is displayed

#### Scenario: Invalid file returns parse error

- **Given** a file with random binary data
- **When** `passwd add mycert --file garbage.bin` runs
- **Then** a descriptive parse error is displayed (not a raw Go error dump)

#### MODIFIED: passwd list

(Previously: list all secrets by name and type without requiring decryption)

The system MUST list secrets with optional `--kind` and `--expiring` filters.

#### Scenario: List by kind (certificate)

- **Given** 5 secrets: 2 certificates, 3 passwords
- **When** `passwd list --kind certificate` runs
- **Then** only the 2 certificate secrets are displayed
- **And** no master password prompt is shown

#### Scenario: List by kind (SSH key)

- **Given** 5 secrets including 1 SSH key
- **When** `passwd list --kind ssh_key` runs
- **Then** only the SSH key secret is displayed

#### Scenario: List expiring certificates

- **Given** 3 certificates expiring in 10, 45, and 90 days
- **When** `passwd list --expiring 30d` runs
- **Then** only the cert expiring in 10 days is returned

#### Scenario: No matching results

- **Given** no certificates in vault
- **When** `passwd list --kind certificate` runs
- **Then** "No secrets found" is displayed

### ADDED REQUIREMENTS

#### R-007: passwd inspect

**Capability**: cli-commands
**Priority**: P1

The system MUST parse and display certificate/key metadata in read-only mode (no storage, no master password prompt).

#### Scenario: Inspect X.509 certificate

- **Given** a valid PEM certificate file
- **When** `passwd inspect cert.pem` runs
- **Then** Subject, Issuer, expiry date, SHA-256 fingerprint, SANs, and key usage are printed to stdout
- **And** no master password is prompted
- **And** nothing is stored in the vault

#### Scenario: Inspect SSH public key

- **Given** a valid SSH public key file
- **When** `passwd inspect id_rsa.pub` runs
- **Then** key type and fingerprint are displayed

#### Scenario: Inspect invalid file

- **Given** a file with corrupt data
- **When** `passwd inspect bad.pem` runs
- **Then** a descriptive parse error is displayed

---

## secret-storage (MODIFIED)

Delta against `openspec/specs/secret-storage/spec.md`.

### MODIFIED REQUIREMENTS

#### MODIFIED: Database Initialization

(Previously: create the database with `secrets`, `schema_version`, `config` tables at schema version 1)

The system MUST create a SQLite database at schema version 2. The `secrets` table MUST include a nullable `metadata TEXT` column for JSON metadata. Existing v1 databases MUST be migrated automatically on `Init()`.

#### Scenario: Fresh database creates v2 schema

- **Given** no existing database file
- **When** `Init(path)` is invoked
- **Then** the `secrets` table includes `metadata TEXT` (nullable)
- **And** schema version in `schema_version` is 2

#### Scenario: v1 to v2 migration

- **Given** an existing database at schema version 1
- **When** `Init(path)` is invoked
- **Then** `ALTER TABLE secrets ADD COLUMN metadata TEXT` is executed
- **And** `schema_version` is updated to 2
- **And** all existing data is preserved

#### MODIFIED: Store Encrypted Secret

(Previously: store encrypted value with name, kind, tags, notes; no `metadata` column)

The system MUST store parsed metadata as a JSON string in the `metadata` column when the secret has metadata populated.

#### Scenario: Store secret with certificate metadata

- **Given** a parsed certificate with expiry, SANs, and fingerprint in metadata
- **When** `Store(secret)` is invoked
- **Then** metadata JSON is stored in the `metadata` column
- **And** the JSON includes an `expiry` field in ISO 8601 format for queryability

#### Scenario: Store secret without metadata

- **Given** a manually added password secret with nil metadata
- **When** `Store(secret)` is invoked
- **Then** the `metadata` column is NULL (backward compatible with v1 behavior)

#### MODIFIED: List Secrets

(Previously: return name, type, tags, created_at, updated_at — ciphertext excluded)

The system MUST return metadata in list results when present, enabling client-side filtering.

#### Scenario: List includes metadata

- **Given** 3 secrets including 1 certificate with metadata, 2 passwords without
- **When** `List()` is invoked
- **Then** all 3 secrets are returned
- **And** the certificate entry includes its metadata; password entries have nil metadata

### ADDED REQUIREMENTS

#### R-008: Query by Expiry

**Capability**: secret-storage
**Priority**: P1

The system MUST support querying certificates expiring within N days using SQLite JSON functions on the `metadata` column.

#### Scenario: List certificates expiring within window

- **Given** 3 certificates with expiry dates at +10, +45, and +90 days from now
- **When** `ListExpiring(30)` is invoked
- **Then** only the certificate expiring in 10 days is returned

#### Scenario: No certificates expiring

- **Given** all certificates expire more than 30 days from now
- **When** `ListExpiring(30)` is invoked
- **Then** an empty list is returned

#### Scenario: Expired certificates excluded

- **Given** a certificate that expired 5 days ago
- **When** `ListExpiring(30)` is invoked
- **Then** it is NOT returned (expired is outside [now, now+N])
