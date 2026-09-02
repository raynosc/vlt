# Delta for sync-server

## MODIFIED Requirements

### Requirement: Authentication

The server MUST reject requests without a valid `Authorization: Bearer <key>` header, AND the provided API key MUST be authorized for the vault UUID in the request path.
(Previously: Only validated the presence and correctness of the Bearer token, not vault UUID ownership.)

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

## ADDED Requirements

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
