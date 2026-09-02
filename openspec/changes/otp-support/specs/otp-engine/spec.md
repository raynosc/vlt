# otp-engine Specification

## Purpose

Core OTP code generation and URI parsing engine. Pure Go stdlib (`crypto/hmac`, `crypto/sha1`, `crypto/sha256`, `encoding/base32`) plus gozxing for QR decode. Generates TOTP (RFC 6238), HOTP (RFC 4226), and Steam Guard codes.

## Requirements

### Requirement: TOTP Code Generation
**Priority**: P0

The system MUST generate valid TOTP codes from an `otpauth://totp` URI. It MUST support SHA1 (default), SHA256, and SHA512. Codes MUST be 6-8 digits per URI.

- **Scenario**: Happy path — GIVEN an `otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP&issuer=Test` URI, WHEN generate is called at a known time step, THEN a 6-digit TOTP code matching reference authenticator output is returned.
- **Scenario**: SHA256 algorithm — GIVEN a URI with `algorithm=SHA256`, WHEN generate is called, THEN the code uses HMAC-SHA256.
- **Scenario**: Custom digits — GIVEN a URI with `digits=8`, WHEN generate is called, THEN an 8-digit code is returned.
- **Scenario**: Invalid base32 secret — GIVEN a URI with non-base32 secret, WHEN generate is called, THEN an error "Invalid secret encoding" is returned.
- **Scenario**: Time step advances — GIVEN a code generated at time T, WHEN generated at T+30s, THEN a different code is returned.

### Requirement: HOTP Code Generation
**Priority**: P0

The system MUST generate valid HOTP codes using HMAC-SHA1 with a caller-provided counter value. Codes MUST be 6-8 digits per URI.

- **Scenario**: RFC 4226 test vector — GIVEN an `otpauth://hotp/Label?secret=GEZDGNBVGY3TQOJQ&counter=0` URI, WHEN generate is called with counter=0, THEN the code matches RFC 4226 Appendix D vector.
- **Scenario**: Counter increment — GIVEN counter=0 produces code A, WHEN generate is called with counter=1, THEN a different code is returned.

### Requirement: DUO URI Parsing
**Priority**: P0

The system MUST parse `duo://` URIs as TOTP. Secret extraction and code generation MUST follow the same path as `otpauth://totp`.

- **Scenario**: Parse — GIVEN a `duo://otp/...` URI with base32 secret, WHEN parsed, THEN secret and algorithm are extracted as if `otpauth://totp`.
- **Scenario**: Generate — GIVEN a parsed `duo://` URI, WHEN TOTP is generated, THEN the code matches the same secret in `otpauth://` format.

### Requirement: Steam URI Parsing
**Priority**: P0

The system MUST parse `steam://` URIs and generate codes using the custom alphabet `23456789BCDFGHJKMNPQRTVWXY`. Codes MUST be 5 characters.

- **Scenario**: Generate — GIVEN a `steam://` URI with valid secret at known time step, WHEN generate is called, THEN a 5-character code using only the custom alphabet is returned.
- **Scenario**: Alphabet validation — GIVEN any generated Steam code, WHEN inspected, THEN all characters are from `23456789BCDFGHJKMNPQRTVWXY`.

### Requirement: QR Image Decode
**Priority**: P1

The system MUST decode a QR code from a PNG image and extract the contained URI string.

- **Scenario**: Decode — GIVEN a valid PNG with QR encoding `otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP`, WHEN decoded, THEN the URI string is returned.
- **Scenario**: No QR — GIVEN a PNG with no QR code, WHEN decode is attempted, THEN an error "No QR code found" is returned.
- **Scenario**: Corrupted image — GIVEN a corrupted image file, WHEN decode is attempted, THEN an error "Unable to decode image" is returned.

### Requirement: QR Terminal Render
**Priority**: P1

The system SHOULD generate terminal block-character QR art from an OTP URI string, scannable by a phone authenticator app.

- **Scenario**: Render — GIVEN an `otpauth://` URI, WHEN terminal QR is generated, THEN block-character output scannable by a phone authenticator is produced.
- **Scenario**: Invalid input — GIVEN a non-URI string, WHEN terminal QR is attempted, THEN an error message is returned or a fallback indicator is shown.
