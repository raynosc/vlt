# API Reference — vlt-sync

[English](SYNC_API.md) | [Español](es/SYNC_API.md)

Zero-knowledge synchronization server for `vlt`. It stores encrypted client vault blobs; it never has access to plaintext secrets.

**Base URL**: `https://your-server.com` (default port `:8443`)

**Security Note**: All communications must be over HTTPS/TLS. The server is designed to run behind a reverse proxy (e.g., Caddy, Nginx) that handles TLS termination.

---

## Authentication

### API Key Authentication

All protected endpoints (except `/v1/register`) require the `Authorization` header:

```http
Authorization: Bearer <api_key>
```

*   **API Key Format**: `<vault_uuid>:<key_hash>`
*   **`<key_hash>`**: SHA-256 hash of the real API key.
*   The server verifies that the `key_hash` belongs to a valid `vault_uuid` before processing the request.

---

## Endpoints

### Health & Status

#### `GET /healthz`

Basic health check. Does not require authentication.

**Response**:
```json
{
  "status": "ok"
}
```

---

#### `GET /readyz`

Verifies if the server is ready to accept requests (database accessible).

**Response**:
```json
{
  "status": "ok"
}
```

**Error Code**:
*   `503 Service Unavailable` — if the store is not initialized.

---

### Registration

#### `POST /v1/register`

Registers a new vault and generates an API key for future authentication.

**Request**:
```json
{
  "vault_uuid": "string (required, UUID v4)",
  "key_hash": "string (required, base64-encoded SHA-256 hash of the API key)"
}
```

**Response** (201 Created):
```json
{
  "vault_uuid": "string",
  "status": "ok"
}
```

**Error Codes**:
*   `400 Bad Request` — invalid body or missing fields.
    ```json
    {
      "error": "vault_uuid is required",
      "code": 400
    }
    ```
*   `409 Conflict` — vault already exists.
    ```json
    {
      "error": "vault already exists",
      "code": 409
    }
    ```
*   `429 Too Many Requests` — rate limit exceeded (5 registrations per IP per hour).
    ```json
    {
      "error": "registration rate limit exceeded",
      "code": 429
    }
    ```

---

### Revocation

#### `POST /v1/revoke`

Revokes an API key, invalidating the corresponding client's access.

**Required Headers**: `Authorization: Bearer <api_key>`

**Request**:
```json
{
  "key_hash": "string (required, base64-encoded SHA-256 hash of the API key)"
}
```

**Response** (200 OK):
```json
{
  "status": "ok"
}
```

**Error Codes**:
*   `400 Bad Request` — invalid body or missing `key_hash`.
*   `401 Unauthorized` — invalid or missing API key.
*   `404 Not Found` — the `key_hash` does not exist.

---

### Vault Operations

#### `POST /v1/vaults/{uuid}/push`

Uploads an encrypted vault blob to the server.

**Required Headers**: `Authorization: Bearer <api_key>`

**Path Parameters**:
*   `uuid` — UUID of the vault.

**Request**:
```json
{
  "seq": 123,
  "blob": "string (required, base64-encoded encrypted vault data)"
}
```

*   `seq`: Client sequence number (for version control and conflict detection).
*   `blob`: Vault data encrypted with the client's `sync_encryption_key`, then base64-encoded.

**Response** (200 OK):
```json
{
  "seq": 124,
  "status": "ok"
}
```

The server increments the sequence and returns it.

**Error Codes**:
*   `400 Bad Request` — invalid body or empty `blob`.
*   `401 Unauthorized` — invalid API key or not authorized for this vault.
*   `404 Not Found` — vault does not exist.
*   `409 Conflict` — `seq` mismatch (the server has a more recent version; the client must pull first).
    ```json
    {
      "error": "sequence mismatch: pull latest first",
      "code": 409
    }
    ```
*   `413 Request Entity Too Large` — `blob` exceeds size limit (10 MB).

---

#### `GET /v1/vaults/{uuid}/pull`

Downloads the encrypted vault blob from the server.

**Required Headers**: `Authorization: Bearer <api_key>`

**Path Parameters**:
*   `uuid` — UUID of the vault.

**Response** (200 OK):
```json
{
  "seq": 124,
  "blob": "string (base64-encoded encrypted vault data)"
}
```

**Error Codes**:
*   `401 Unauthorized` — invalid API key or not authorized for this vault.
*   `404 Not Found` — vault does not exist or has no data (`no blob for this vault`).

---

#### `GET /v1/vaults/{uuid}/status`

Retrieves vault metadata from the server (without the blob content).

**Required Headers**: `Authorization: Bearer <api_key>`

**Path Parameters**:
*   `uuid` — UUID of the vault.

**Response** (200 OK):
```json
{
  "vault_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "seq": 124,
  "last_updated": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
*   `401 Unauthorized` — invalid API key or not authorized for this vault.
*   `404 Not Found` — vault does not exist.

---

## Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| `POST /v1/register` | 5 requests | Per IP, per hour |
| `POST /v1/revoke` | 10 requests | Per API key, per minute |
| Other endpoints | 100 requests | Per API key, per minute |

When the rate limit is exceeded, the server returns `429 Too Many Requests` with the `Retry-After` header indicating the remaining seconds.

---

## Error Responses

All error endpoints return JSON with the following structure:

```json
{
  "error": "human-readable error message",
  "code": 400
}
```

HTTP status codes used:

*   `400 Bad Request` — Malformed request.
*   `401 Unauthorized` — Authentication failed.
*   `404 Not Found` — Resource not found.
*   `409 Conflict` — State conflict (e.g., seq mismatch).
*   `413 Request Entity Too Large` — Payload too large.
*   `429 Too Many Requests` — Rate limit exceeded.
*   `500 Internal Server Error` — Internal server error.

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VLT_SYNC_ADDR` | Listening address and port | `:8443` |
| `VLT_SYNC_DB_PATH` | Path to the server's SQLite file | `./sync-server.db` |
| `VLT_SYNC_TLS_CERT` | Path to TLS certificate (PEM) | (required) |
| `VLT_SYNC_TLS_KEY` | Path to TLS private key (PEM) | (required) |

---

## Example Usage (cURL)

### Register a new vault

```bash
curl -X POST https://localhost:8443/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "vault_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "key_hash": "base64_encoded_sha256_of_api_key"
  }'
```

### Upload encrypted data (push)

```bash
curl -X POST https://localhost:8443/v1/vaults/550e8400-e29b-41d4-a716-446655440000/push \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000:base64_key_hash" \
  -H "Content-Type: application/json" \
  -d '{
    "seq": 1,
    "blob": "base64_encrypted_vault_data"
  }'
```

### Download data (pull)

```bash
curl -X GET https://localhost:8443/v1/vaults/550e8400-e29b-41d4-a716-446655440000/pull \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000:base64_key_hash"
```

### Verify server status

```bash
curl -X GET https://localhost:8443/healthz
```

---

## Security Notes

*   **Zero-Knowledge**: The server only stores encrypted blobs. It cannot decrypt, read, or modify the secrets.
*   **TLS Mandatory**: The server must run over HTTPS/TLS. It is recommended to use a reverse proxy (Caddy, Nginx) to manage certificates.
*   **API Keys**: API keys are UUID-scoped. A compromise of one key only affects the associated vault.
*   **Rate Limiting**: Protects against abuse and brute-force attacks.
*   **Sequence Control**: The sequence mechanism prevents accidentally overwriting more recent data (though `vlt sync push --force` can bypass this check).
