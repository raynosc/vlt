# Delta for sync-server

## MODIFIED Requirements

### Requirement: Vault Registration

The server MUST accept `POST /v1/vaults` to register a new vault with a generated UUID and
associated API key. The response MUST include `vault_seq`, reflecting the current sequence
number of the vault (0 for a brand-new vault, or the existing sequence if the vault already
has a blob). The opaque-blob storage model is unchanged.
(Previously: RegisterResponse did not include vault_seq.)

#### Scenario: Successful registration — new vault

- GIVEN a valid registration request for a new vault
- WHEN `POST /v1/vaults` is called
- THEN the server SHALL return 201 with the vault UUID
- AND the response SHALL include vault_seq=0
- AND the vault record SHALL be persisted

#### Scenario: Re-registration of an existing vault — returns 409 Conflict

- GIVEN a vault UUID that already exists on the server
- WHEN `POST /v1/vaults` is called again (attempted re-registration)
- THEN the server SHALL return 409 Conflict (anti-hijack by design)
- AND the existing blob SHALL NOT be modified
- NOTE: handleRegister returns 409 on any re-registration attempt. VaultSeq
  from the register response is therefore always 0 for the vault creator.
  A device adopting an existing vault anchors its registration_seq via the
  pre-flight GET /status (TOFU), not via the register endpoint.

#### Scenario: Blob not found (existing — retained)

- GIVEN a vault UUID with no stored blob
- WHEN `GET /v1/vaults/{uuid}/blob` is called
- THEN the server SHALL return 404
