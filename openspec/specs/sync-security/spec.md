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

### Requirement: Config Format Version Gate (nil-AAD prohibition)

The config value `config_format_version=2` MUST be written only after BOTH `api_key` AND
`sync_encryption_key` re-wrapping succeed atomically. Once `config_format_version >= 2`
is recorded, `UnwrapConfigValue` MUST NOT fall back to nil-AAD decryption. Legacy vaults
(version < 2 or version absent) MAY still use the nil-AAD fallback during the migration
path only.

#### Scenario: Version=2 written only after both re-wraps succeed

- GIVEN the migration flow attempts to re-wrap api_key and sync_encryption_key
- WHEN both re-wraps complete without error
- THEN config_format_version SHALL be set to 2
- AND both updated values SHALL be persisted atomically

#### Scenario: Version=2 NOT written if api_key re-wrap fails

- GIVEN the migration flow attempts to re-wrap api_key and sync_encryption_key
- WHEN api_key re-wrap returns an error
- THEN config_format_version SHALL NOT be updated to 2
- AND the original config values SHALL remain unchanged

#### Scenario: Version=2 NOT written if sync_encryption_key re-wrap fails

- GIVEN the migration flow attempts to re-wrap api_key and sync_encryption_key
- WHEN sync_encryption_key re-wrap returns an error
- THEN config_format_version SHALL NOT be updated to 2
- AND the original config values SHALL remain unchanged

#### Scenario: UnwrapConfigValue with version>=2 rejects nil-AAD ciphertext

- GIVEN a config with config_format_version=2
- WHEN UnwrapConfigValue is called with a ciphertext that was wrapped with nil AAD
- THEN it SHALL return an authentication error
- AND SHALL NOT return plaintext

#### Scenario: Legacy vault migrates via nil-AAD fallback

- GIVEN a config with config_format_version absent or < 2
- WHEN UnwrapConfigValue is called
- THEN it MAY attempt nil-AAD decryption as fallback
- AND on success it SHALL proceed with the decrypted value

#### Scenario: Migrated vault cannot be downgraded by replay

- GIVEN a vault with config_format_version=2
- AND an attacker replays a config blob from before migration (nil-AAD wrapped)
- WHEN UnwrapConfigValue processes the replayed blob
- THEN it SHALL fail authentication
- AND SHALL NOT expose plaintext
