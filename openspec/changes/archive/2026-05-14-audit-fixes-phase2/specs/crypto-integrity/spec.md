# Delta for crypto-integrity

## ADDED Requirements

### Requirement: Argon2 Parameter Fidelity

The crypto engine MUST read stored Argon2 parameters from the vault header during unlock. If no stored parameters exist, it SHALL fall back to compile-time defaults.

#### Scenario: Unlock with custom params

- GIVEN a vault created with non-default Argon2 parameters
- WHEN the vault is unlocked
- THEN the engine SHALL derive the key using the stored parameters

#### Scenario: Unlock legacy vault

- GIVEN a vault with no stored Argon2 parameters
- WHEN the vault is unlocked
- THEN the engine SHALL fall back to default parameters

### Requirement: OTP Label Path Unescaping

The system MUST decode percent-encoded OTP label paths using `url.PathUnescape` before display or matching.

#### Scenario: Escaped label in URI

- GIVEN an OTP URI with a percent-encoded label (e.g., `Issuer%3AUser`)
- WHEN parsing the URI
- THEN the label SHALL be correctly unescaped (e.g., `Issuer:User`)

#### Scenario: Plain label unchanged

- GIVEN an OTP URI with an already-unescaped label
- WHEN parsing the URI
- THEN the label SHALL remain unchanged

### Requirement: Timestamp Parse Error Propagation

The store MUST propagate `time.Parse` errors to callers instead of silently swallowing them.

#### Scenario: Corrupted timestamp

- GIVEN a secret record with a malformed `created_at` timestamp
- WHEN reading the secret
- THEN the function SHALL return a parse error

#### Scenario: Valid timestamp succeeds

- GIVEN a secret record with a valid RFC 3339 timestamp
- WHEN reading the secret
- THEN the function SHALL succeed without error

### Requirement: Safe OTP URI Construction

The system MUST construct OTP URIs using `url.URL` and `url.Values` to ensure proper query encoding. Secret names containing reserved characters MUST be safely encoded.

#### Scenario: Secret name with query character

- GIVEN a secret named `what?secret`
- WHEN constructing an OTP URI
- THEN the name SHALL be query-encoded so the URI remains valid

#### Scenario: Standard name encoded correctly

- GIVEN a secret named `github-token`
- WHEN constructing an OTP URI
- THEN the resulting URI SHALL be correctly formed
