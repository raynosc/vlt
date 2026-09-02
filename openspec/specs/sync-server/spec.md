# sync-server Specification

## Purpose

Standalone REST API server that stores and serves encrypted vault blobs keyed by vault UUID, authenticates via API keys, enforces TLS, rate-limits per key, and exposes health status. Designed for K8s deployment as a single container with SQLite on PVC.

## Requirements

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

### Requirement: Encrypted Blob Storage

The server MUST accept opaque blobs via `PUT /v1/vaults/{uuid}/blob` and serve via `GET /v1/vaults/{uuid}/blob`.

#### Scenario: Store and retrieve

- GIVEN a registered vault with valid API key
- WHEN a client PUTs an encrypted blob
- THEN the server SHALL return 200
- AND when GETting the blob, the server SHALL return identical bytes

#### Scenario: Blob not found

- GIVEN a vault UUID with no stored blob
- WHEN `GET /v1/vaults/{uuid}/blob` is called
- THEN the server SHALL return 404

### Requirement: Vault Status

The server MUST expose `GET /v1/vaults/{uuid}/status` returning version metadata without blob content.

#### Scenario: Status response

- GIVEN a registered vault
- WHEN `GET /v1/vaults/{uuid}/status` is called
- THEN the response SHALL include last_updated and version
- AND SHALL NOT include the blob body

### Requirement: Authentication

The server MUST reject requests without a valid `Authorization: Bearer <key>` header, AND the provided API key MUST be authorized for the vault UUID in the request path.

#### Scenario: Missing auth header

- GIVEN a request without Authorization header
- WHEN any vault endpoint is called
- THEN the server SHALL return 401

#### Scenario: Invalid key

- GIVEN a request with an invalid Bearer token
- WHEN any vault endpoint is called
- THEN the server SHALL return 403

#### Scenario: Valid key for wrong vault

- GIVEN a valid API key belonging to vault A
- WHEN `GET /v1/vaults/{vault-B-uuid}/blob` is called
- THEN the server SHALL return 403

### Requirement: TLS Enforcement

The server MUST only accept TLS-encrypted connections.

#### Scenario: Plain HTTP rejected

- GIVEN a plain HTTP request
- WHEN connecting to the server
- THEN the server SHALL reject the connection

### Requirement: Rate Limiting

The server MUST rate-limit per API key to a configurable requests-per-minute threshold.

#### Scenario: Rate limit hit

- GIVEN a client exceeding the configured rate limit
- WHEN making additional requests
- THEN the server SHALL return 429

### Requirement: Default Bind Address

The server SHALL default to binding on `127.0.0.1` unless explicitly configured otherwise.

#### Scenario: Default localhost bind

- GIVEN no bind address is configured
- WHEN the server starts
- THEN it SHALL listen on `127.0.0.1`

#### Scenario: Explicit override

- GIVEN a configured bind address of `0.0.0.0`
- WHEN the server starts
- THEN it SHALL listen on the configured address

### Requirement: Registration Rate Limiting

The server MUST rate-limit `POST /v1/vaults` by source IP address to prevent unauthenticated registration DoS.

#### Scenario: Exceeded threshold

- GIVEN a client that has exceeded the per-IP registration threshold
- WHEN another `POST /v1/vaults` is made from the same IP
- THEN the server SHALL return 429

#### Scenario: Under threshold

- GIVEN a client below the per-IP registration threshold
- WHEN `POST /v1/vaults` is called
- THEN the server SHALL return 201

### Requirement: Database File Permissions

The server MUST create the SQLite database file with permissions `0o600`.

#### Scenario: New database created

- GIVEN a new database file is created
- WHEN checking filesystem permissions
- THEN the mode SHALL be `0o600`

#### Scenario: Existing database untouched

- GIVEN an existing database file
- WHEN the server starts
- THEN existing permissions SHALL NOT be modified

### Requirement: Health Endpoint

The server MUST expose `GET /health`.

#### Scenario: Health check

- GIVEN a running server
- WHEN `GET /health` is called
- THEN the server SHALL return 200 with status "ok"

### Requirement: Zero-Knowledge

The server MUST NOT decrypt, inspect, or transform stored blob content.

#### Scenario: Opaque blob handling

- GIVEN an encrypted blob stored on the server
- WHEN any server operation occurs
- THEN the server SHALL process it as opaque bytes
- AND SHALL NOT attempt decryption or content inspection
