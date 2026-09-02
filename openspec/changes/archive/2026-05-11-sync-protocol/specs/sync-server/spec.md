# sync-server Specification

## Purpose

Standalone REST API server that stores and serves encrypted vault blobs keyed by vault UUID, authenticates via API keys, enforces TLS, rate-limits per key, and exposes health status. Designed for K8s deployment as a single container with SQLite on PVC.

## Requirements

### Requirement: Vault Registration

The server MUST accept `POST /v1/vaults` to register a new vault with a generated UUID and associated API key.

#### Scenario: Successful registration

- GIVEN a valid registration request
- WHEN `POST /v1/vaults` is called
- THEN the server SHALL return 201 with the vault UUID
- AND SHALL persist the vault record

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

The server MUST reject requests without a valid `Authorization: Bearer <key>` header.

#### Scenario: Missing auth header

- GIVEN a request without Authorization header
- WHEN any vault endpoint is called
- THEN the server SHALL return 401

#### Scenario: Invalid key

- GIVEN a request with an invalid Bearer token
- WHEN any vault endpoint is called
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
