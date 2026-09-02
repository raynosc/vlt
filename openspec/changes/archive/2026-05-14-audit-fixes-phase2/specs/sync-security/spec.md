# Delta for sync-security

## ADDED Requirements

### Requirement: TLS Enforcement on Sync Client

The sync client MUST reject `http://` server URLs unless the `--insecure` flag is explicitly provided.

#### Scenario: HTTP URL rejected

- GIVEN a sync server URL with `http://` scheme
- WHEN `NewClient` is called without `--insecure`
- THEN it SHALL return an error

#### Scenario: HTTPS URL accepted

- GIVEN a sync server URL with `https://` scheme
- WHEN `NewClient` is called
- THEN it SHALL succeed without error

#### Scenario: Insecure flag bypasses check

- GIVEN an `http://` URL
- WHEN `NewClient` is called with `--insecure`
- THEN it SHALL succeed

### Requirement: API Key Masking

The CLI MUST mask API keys in output, displaying only the last 4 characters. All other characters SHALL be replaced with `*`.

#### Scenario: sync init prints masked key

- GIVEN `vlt sync init` generates a new API key
- WHEN the key is printed to the terminal
- THEN only the last 4 characters are visible

### Requirement: Encrypted D-Bus Session on Linux

On Linux, the keychain integration MUST open an encrypted D-Bus session using `dh-ietf1024-sha256-aes128-cbc-pkcs7`. If the encrypted session is unavailable, it SHALL gracefully fall back to `plain`.

#### Scenario: Encrypted session opened

- GIVEN a Linux system with Secret Service available
- WHEN opening a D-Bus session
- THEN the session algorithm SHALL be `dh-ietf1024-sha256-aes128-cbc-pkcs7`

#### Scenario: Graceful fallback

- GIVEN an older distro without encrypted session support
- WHEN opening a D-Bus session
- THEN it SHALL fall back to `plain` without error
