# cert-parsing Specification

## Purpose

Certificate and SSH key format parsing with metadata extraction. Pure decode-only — no private key exposure, no certificate generation, no chain validation. Parsed metadata is stored as JSON for queryability (expiry, fingerprint, type filtering).

## Requirements

### Requirement: Parse PEM X.509 Certificate

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

### Requirement: Parse SSH Private Key

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

### Requirement: Parse SSH Public Key

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

### Requirement: Parse PKCS#12 Bundle

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

### Requirement: Format Auto-detection

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

### Requirement: Parse Error Handling

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
