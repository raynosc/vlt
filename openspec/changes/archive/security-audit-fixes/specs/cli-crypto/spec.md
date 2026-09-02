# Delta for cli-crypto

## ADDED Requirements

### Requirement: Atomic HOTP Counter

The CLI MUST atomically increment the HOTP counter to prevent race conditions during concurrent code generation.

#### Scenario: Concurrent increments

- GIVEN two simultaneous HOTP generation requests
- WHEN both increment the counter
- THEN each SHALL receive a unique counter value without data races

#### Scenario: Sequential increments

- GIVEN sequential HOTP generation requests
- WHEN each increments the counter
- THEN the counter SHALL increase monotonically by one per request

### Requirement: Recovery Key Error Handling

The crypto package MUST return an error for recovery keys with invalid byte length instead of panicking.

#### Scenario: Invalid length

- GIVEN a recovery key with an invalid byte length
- WHEN encoding the recovery key
- THEN the function SHALL return an error

#### Scenario: Valid length

- GIVEN a recovery key with a valid byte length
- WHEN encoding the recovery key
- THEN the function SHALL succeed without error
