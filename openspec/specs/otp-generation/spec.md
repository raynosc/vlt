# Delta for otp-generation

## MODIFIED Requirements

### Requirement: TOTP Code Generation

The system MUST generate valid TOTP codes from an `otpauth://totp` URI. It MUST support SHA1 (default), SHA256, and SHA512. Codes MUST be 6-8 digits per URI. `GenerateTOTP` MUST return an error when the `digits` parameter is outside the range [5, 8]; digits=5 is explicitly valid (Steam compatibility). No panic is permitted for any integer value of `digits`.

(Previously: `digits` was unvalidated — digits=0 silently returned "0"; digits<0 caused a divide-by-zero panic.)

#### Scenario: Happy path — TOTP (unchanged)

- GIVEN an `otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP&issuer=Test` URI
- WHEN generate is called at a known time step
- THEN a 6-digit TOTP code matching reference authenticator output is returned

#### Scenario: SHA256 algorithm (unchanged)

- GIVEN a URI with `algorithm=SHA256`
- WHEN generate is called
- THEN the code uses HMAC-SHA256

#### Scenario: Custom digits — valid values 5, 6, 8

- GIVEN a valid TOTP URI
- WHEN `GenerateTOTP` is called with digits=5, then digits=6, then digits=8
- THEN each call returns a code of exactly that many digits with no error

#### Scenario: Invalid base32 secret (unchanged)

- GIVEN a URI with a non-base32 secret
- WHEN generate is called
- THEN an error "Invalid secret encoding" is returned

#### Scenario: M7 — digits=0 returns error, not "0"

- GIVEN a valid TOTP URI
- WHEN `GenerateTOTP` is called with digits=0
- THEN a non-nil error is returned
- AND the returned code string is empty (not "0")
- AND no panic occurs

#### Scenario: M7 — digits=-1 returns error, no panic

- GIVEN a valid TOTP URI
- WHEN `GenerateTOTP` is called with digits=-1
- THEN a non-nil error is returned
- AND no divide-by-zero panic occurs

#### Scenario: M7 — digits=9 returns error

- GIVEN a valid TOTP URI
- WHEN `GenerateTOTP` is called with digits=9
- THEN a non-nil error is returned

---

### Requirement: HOTP Code Generation

The system MUST generate valid HOTP codes using HMAC-SHA1 with a caller-provided counter value. Codes MUST be 6-8 digits per URI. `GenerateHOTP` MUST return an error when the `digits` parameter is outside the range [5, 8]; digits=5 is explicitly valid. No panic is permitted for any integer value of `digits`.

(Previously: `digits` was unvalidated — digits=0 silently returned "0"; digits<0 caused a divide-by-zero panic.)

#### Scenario: RFC 4226 test vector (unchanged)

- GIVEN an `otpauth://hotp/Label?secret=GEZDGNBVGY3TQOJQ&counter=0` URI
- WHEN generate is called with counter=0
- THEN the code matches RFC 4226 Appendix D vector

#### Scenario: Counter increment (unchanged)

- GIVEN counter=0 produces code A
- WHEN generate is called with counter=1
- THEN a different code is returned

#### Scenario: M7 — digits=0 returns error, not "0"

- GIVEN a valid HOTP URI
- WHEN `GenerateHOTP` is called with digits=0
- THEN a non-nil error is returned
- AND the returned code string is empty (not "0")
- AND no panic occurs

#### Scenario: M7 — digits=-1 returns error, no panic

- GIVEN a valid HOTP URI
- WHEN `GenerateHOTP` is called with digits=-1
- THEN a non-nil error is returned
- AND no divide-by-zero panic occurs

#### Scenario: M7 — digits=9 returns error

- GIVEN a valid HOTP URI
- WHEN `GenerateHOTP` is called with digits=9
- THEN a non-nil error is returned

#### Scenario: M7 — digits=5 success

- GIVEN a valid HOTP URI
- WHEN `GenerateHOTP` is called with digits=5
- THEN a 5-character code is returned with no error

---

### Requirement: truncate Bounds Guard (future-proof)

> NOTE: This guard is NOT reachable with current hash algorithms. SHA1/256/512 produce ≥ 20 bytes; the maximum HMAC offset (15) reads at most index 18 — always within bounds. The guard is a defensive measure against future algorithms with shorter output.

The internal `truncate` function MUST return an error if the HMAC byte slice is shorter than `offset + 4` bytes, rather than panicking with an index-out-of-range.

(Previously: no bounds check; the OOB path was unreachable but unguarded.)

#### Scenario: M7 — short HMAC slice triggers error (future-proof unit test)

- GIVEN a synthetic HMAC byte slice shorter than `offset + 4` bytes
- WHEN `truncate` is called with an offset that would exceed the slice bounds
- THEN a non-nil error is returned
- AND no index-out-of-range panic occurs
