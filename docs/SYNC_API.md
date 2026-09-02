# API Reference — vlt-sync

Servidor de sincronización zero-knowledge para `vlt`. Almacena blobs encriptados de vaults de clientes; nunca tiene acceso a los secretos en texto plano.

**Base URL**: `https://your-server.com` (por defecto puerto `:8443`)

**Nota de seguridad**: Todas las comunicaciones deben realizarse sobre HTTPS/TLS. El servidor está diseñado para ejecutarse detrás de un proxy inverso (ej. Caddy, Nginx) que maneje la terminación TLS.

---

## Authentication

### API Key Authentication

Todos los endpoints protegidos (excepto `/v1/register`) requieren el header `Authorization`:

```http
Authorization: Bearer <api_key>
```

*   **Formato del API Key**: `<vault_uuid>:<key_hash>`
*   **`<key_hash>`**: Hash SHA-256 de la clave API real.
*   El servidor verifica que el `key_hash` pertenezca a un `vault_uuid` válido antes de procesar la solicitud.

---

## Endpoints

### Health & Status

#### `GET /healthz`

Health check básico. No requiere autenticación.

**Respuesta**:
```json
{
  "status": "ok"
}
```

---

#### `GET /readyz`

Verifica si el servidor está listo para aceptar solicitudes (base de datos accesible).

**Respuesta**:
```json
{
  "status": "ok"
}
```

**Código de error**:
*   `503 Service Unavailable` — si el store no está inicializado.

---

### Registration

#### `POST /v1/register`

Registra un nuevo vault y genera un API key para autenticación futura.

**Request**:
```json
{
  "vault_uuid": "string (required, UUID v4)",
  "key_hash": "string (required, base64-encoded SHA-256 hash of the API key)"
}
```

**Respuesta** (201 Created):
```json
{
  "vault_uuid": "string",
  "status": "ok"
}
```

**Códigos de error**:
*   `400 Bad Request` — cuerpo inválido o campos faltantes.
    ```json
    {
      "error": "vault_uuid is required",
      "code": 400
    }
    ```
*   `409 Conflict` — el vault ya existe.
    ```json
    {
      "error": "vault already exists",
      "code": 409
    }
    ```
*   `429 Too Many Requests` — rate limit excedido (5 registros por IP por hora).
    ```json
    {
      "error": "registration rate limit exceeded",
      "code": 429
    }
    ```

---

### Revocation

#### `POST /v1/revoke`

Revoca un API key, invalidando el acceso del cliente correspondiente.

**Headers requeridos**: `Authorization: Bearer <api_key>`

**Request**:
```json
{
  "key_hash": "string (required, base64-encoded SHA-256 hash of the API key)"
}
```

**Respuesta** (200 OK):
```json
{
  "status": "ok"
}
```

**Códigos de error**:
*   `400 Bad Request` — cuerpo inválido o `key_hash` faltante.
*   `401 Unauthorized` — API key inválida o no proporcionada.
*   `404 Not Found` — la `key_hash` no existe.

---

### Vault Operations

#### `POST /v1/vaults/{uuid}/push`

Sube un blob encriptado del vault al servidor.

**Headers requeridos**: `Authorization: Bearer <api_key>`

**Parámetros de path**:
*   `uuid` — UUID del vault.

**Request**:
```json
{
  "seq": 123,
  "blob": "string (required, base64-encoded encrypted vault data)"
}
```

*   `seq`: Número de secuencia del cliente (para control de versiones y detección de conflictos).
*   `blob`: Datos del vault encriptados con la `sync_encryption_key` del cliente, luego codificados en base64.

**Respuesta** (200 OK):
```json
{
  "seq": 124,
  "status": "ok"
}
```

El servidor incrementa la secuencia y la devuelve.

**Códigos de error**:
*   `400 Bad Request` — cuerpo inválido o `blob` vacío.
*   `401 Unauthorized` — API key no válida o no autorizada para este vault.
*   `404 Not Found` — el vault no existe.
*   `409 Conflict` — `seq` no coincide (el servidor tiene una versión más reciente; el cliente debe hacer `pull` primero).
    ```json
    {
      "error": "sequence mismatch: pull latest first",
      "code": 409
    }
    ```
*   `413 Request Entity Too Large` — `blob` excede el límite de tamaño (10 MB).

---

#### `GET /v1/vaults/{uuid}/pull`

Descarga el blob encriptado del vault desde el servidor.

**Headers requeridos**: `Authorization: Bearer <api_key>`

**Parámetros de path**:
*   `uuid` — UUID del vault.

**Respuesta** (200 OK):
```json
{
  "seq": 124,
  "blob": "string (base64-encoded encrypted vault data)"
}
```

**Códigos de error**:
*   `401 Unauthorized` — API key no válida o no autorizada para este vault.
*   `404 Not Found` — el vault no existe o no tiene datos (`no blob for this vault`).

---

#### `GET /v1/vaults/{uuid}/status`

Obtiene metadatos del vault en el servidor (sin el contenido del blob).

**Headers requeridos**: `Authorization: Bearer <api_key>`

**Parámetros de path**:
*   `uuid` — UUID del vault.

**Respuesta** (200 OK):
```json
{
  "vault_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "seq": 124,
  "last_updated": "2024-01-15T10:30:00Z"
}
```

**Códigos de error**:
*   `401 Unauthorized` — API key no válida o no autorizada para este vault.
*   `404 Not Found` — el vault no existe.

---

## Rate Limiting

| Endpoint | Límite | Ventana |
|----------|--------|---------|
| `POST /v1/register` | 5 requests | Por IP, por hora |
| `POST /v1/revoke` | 10 requests | Por API key, por minuto |
| Otros endpoints | 100 requests | Por API key, por minuto |

Cuando se excede el rate limit, el servidor devuelve `429 Too Many Requests` con el header `Retry-After` indicando los segundos restantes.

---

## Error Responses

Todos los endpoints de error devuelven JSON con la siguiente estructura:

```json
{
  "error": "human-readable error message",
  "code": 400
}
```

Los códigos de estado HTTP usados son:

*   `400 Bad Request` — Solicitud mal formada.
*   `401 Unauthorized` — Autenticación fallida.
*   `404 Not Found` — Recurso no encontrado.
*   `409 Conflict` — Conflicto de estado (ej. seq mismatch).
*   `413 Request Entity Too Large` — Payload demasiado grande.
*   `429 Too Many Requests` — Rate limit excedido.
*   `500 Internal Server Error` — Error interno del servidor.

---

## Environment Variables

| Variable | Descripción | Default |
|----------|-------------|---------|
| `VLT_SYNC_ADDR` | Dirección y puerto de escucha | `:8443` |
| `VLT_SYNC_DB_PATH` | Ruta al archivo SQLite del servidor | `./sync-server.db` |
| `VLT_SYNC_TLS_CERT` | Ruta al certificado TLS (PEM) | (requerido) |
| `VLT_SYNC_TLS_KEY` | Ruta a la clave privada TLS (PEM) | (requerido) |

---

## Example Usage (cURL)

### Registrar un nuevo vault

```bash
curl -X POST https://localhost:8443/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "vault_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "key_hash": "base64_encoded_sha256_of_api_key"
  }'
```

### Subir datos encriptados (push)

```bash
curl -X POST https://localhost:8443/v1/vaults/550e8400-e29b-41d4-a716-446655440000/push \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000:base64_key_hash" \
  -H "Content-Type: application/json" \
  -d '{
    "seq": 1,
    "blob": "base64_encrypted_vault_data"
  }'
```

### Descargar datos (pull)

```bash
curl -X GET https://localhost:8443/v1/vaults/550e8400-e29b-41d4-a716-446655440000/pull \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000:base64_key_hash"
```

### Verificar estado del servidor

```bash
curl -X GET https://localhost:8443/healthz
```

---

## Security Notes

*   **Zero-Knowledge**: El servidor almacena únicamente blobs encriptados. No puede desencriptar, leer ni modificar los secretos.
*   **TLS Obligatorio**: El servidor debe ejecutarse sobre HTTPS/TLS. Se recomienda usar un proxy inverso (Caddy, Nginx) para gestionar certificados.
*   **API Keys**: Las claves API son UUID-scoped. Un compromiso de una clave solo afecta al vault asociado.
*   **Rate Limiting**: Protege contra abuso y ataques de fuerza bruta.
*   **Sequence Control**: El mecanismo de secuencias previene sobrescribir datos más recientes accidentalmente (aunque `vlt sync push --force` puede ignorar este control).