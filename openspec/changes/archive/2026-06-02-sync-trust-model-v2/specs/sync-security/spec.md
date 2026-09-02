# Delta for sync-security

## Threat Model Addendum

Adversary: migration path where a vault was created before key-name AAD binding was
introduced. A nil-AAD fallback on already-migrated vaults silently undoes the security
property. The version gate makes that regression impossible after migration.

## ADDED Requirements

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
