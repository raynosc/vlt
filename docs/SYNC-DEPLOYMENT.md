# vlt-sync — Guía Maestra de Despliegue, mTLS y Sincronización Multi-Dispositivo de Principio a Fin

Esta guía detalla el flujo de trabajo completo para desplegar y utilizar la sincronización **Zero-Knowledge + Zero-Trust mTLS** de `vlt` entre múltiples clientes (macOS, Windows, Linux) y un servidor central (`vlt-sync`).

---

## 📑 Tabla de Contenidos

1. [Arquitectura y Principios de Seguridad](#1-arquitectura-y-principios-de-seguridad)
2. [Paso 1: Generación de la Infraestructura PKI (Certificados mTLS)](#paso-1-generación-de-la-infraestructura-pki-certificados-mtls)
3. [Paso 2: Despliegue del Servidor `vlt-sync` en Docker / VM](#paso-2-despliegue-del-servidor-vlt-sync-en-docker--vm)
4. [Paso 3: Configuración y Registro del Cliente Principal (Mac)](#paso-3-configuración-y-registro-del-cliente-principal-mac)
5. [Paso 4: Conexión de un Segundo Dispositivo (PC Windows / VM Linux)](#paso-4-conexión-de-un-segundo-dispositivo-pc-windows--vm-linux)
6. [Paso 5: Sincronización en Tiempo Real y Notificaciones de Escritorio](#paso-5-sincronización-en-tiempo-real-y-notificaciones-de-escritorio)
7. [Paso 6: Gestión Multi-Bóveda (`vault` y `work`)](#paso-6-gestión-multi-bóveda-vault-y-work)
8. [Paso 7: Guía de Solución de Problemas (Troubleshooting)](#paso-7-guía-de-solución-de-problemas-troubleshooting)

---

## 1. Arquitectura y Principios de Seguridad

```
┌─────────────────────────────────────────────────────────────┐
│                 DISPOSITIVOS CLIENTES (Mac / Windows)       │
│                                                             │
│  1. Cifrado local con clave maestra (AES-256-GCM + AAD)     │
│  2. Base de datos SQLite local: ~/.config/passwd/*.sqlite   │
│  3. Cifrado del payload de red con `sync_encryption_key`    │
│  4. Autenticación mutua con certificado de cliente (mTLS)   │
└─────────────┬───────────────────────────────────────────────┘
              │
              │ HTTPS (TLS 1.3 / mTLS / HTTP/2)
              ▼
┌─────────────────────────────────────────────────────────────┐
│                 SERVIDOR vlt-sync (VM / Docker)             │
│                                                             │
│  • Puerto TCP: 8443                                         │
│  • Servidor Ciego: Solo guarda blobs cifrados y secuencias  │
│  • Emisor en tiempo real: Server-Sent Events (SSE)          │
│  • Base de datos del servidor: /data/sync.db                │
└─────────────────────────────────────────────────────────────┘
```

* **Zero-Knowledge**: El servidor nunca conoce contraseñas, nombres de secretos ni notas. Todo el cifrado/descifrado se ejecuta en la RAM del cliente.
* **Zero-Trust mTLS**: El servidor rechaza en el handshake a cualquier conexión que no presente un certificado de cliente firmado por la CA (`ClientAuth = tls.RequireAndVerifyClientCert`).
* **Concurrencia Atómica (CAS / LWW)**: Control de versiones monótonas (`seq`). Si dos dispositivos guardan simultáneamente, el conflicto se resuelve con marcas de tiempo efectivas (*Last-Write-Wins*) y lápidas (*tombstones*) para borrados.

---

## Paso 1: Generación de la Infraestructura PKI (Certificados mTLS)

Toda la infraestructura de certificados se genera con el comando nativo `vlt pki` en tu máquina principal (Mac). Cumple estrictamente con RFC 5280 y los requisitos de Apple (curvas ECDSA P-256, validez <= 398 días, SANs por IP/DNS):

```bash
# 1. Generar CA, Certificado de Servidor (con IP y dominios) y Certificado del Cliente Mac:
./bin/vlt pki generate --out ./certs --hosts "192.168.0.104,localhost" --client "mac-laptop"

# 2. Generar Certificado de Cliente para tu PC Windows:
./bin/vlt pki client --ca ./certs/ca.pem --ca-key ./certs/ca-key.pem --name "windows-pc" --out ./certs
```

### 📂 Archivos generados en `./certs/`:
| Archivo | Rol | Dónde se instala |
| :--- | :--- | :--- |
| `ca.pem` | Certificado de la Autoridad Certificadora Raíz | En el Servidor y en **todos** los Clientes |
| `ca-key.pem` | Clave privada de la CA | Guardar segura/offline (para firmar futuros clientes) |
| `server.pem` | Certificado TLS del Servidor (con SANs) | En el Servidor |
| `server-key.pem` | Clave privada del Servidor | En el Servidor |
| `client.pem` | Certificado mTLS de tu Mac | En tu Mac |
| `client-key.pem` | Clave privada de tu Mac | En tu Mac |
| `windows-pc.pem` | Certificado mTLS de tu PC Windows | En tu PC Windows |
| `windows-pc-key.pem`| Clave privada de tu PC Windows | En tu PC Windows |

---

## Paso 2: Despliegue del Servidor `vlt-sync` en Docker / VM

### 1. Copiar los certificados al servidor:
Desde tu máquina local, transfiere los archivos necesarios a la VM:
```bash
scp certs/ca.pem certs/server.pem certs/server-key.pem usuario@192.168.0.104:/opt/vlt-sync/certs/
```

### 2. Levantar el servicio con Docker Compose:
En la VM, en la carpeta `/opt/vlt-sync/`:

```yaml
# docker-compose.yml
services:
  vlt-sync:
    build: .
    image: vlt-sync:latest
    container_name: vlt-sync
    restart: unless-stopped
    ports:
      - "8443:8443"
    environment:
      - VLT_SYNC_ADDR=:8443
      - VLT_SYNC_DB_PATH=/data/sync.db
      - VLT_SYNC_TLS_CERT=/certs/server.pem
      - VLT_SYNC_TLS_KEY=/certs/server-key.pem
      - VLT_SYNC_TLS_CLIENT_CA=/certs/ca.pem
    volumes:
      - ./data:/data
      - ./certs:/certs:ro
    healthcheck:
      test: ["CMD-SHELL", "curl -k -f https://localhost:8443/healthz || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
```

```bash
docker compose up -d
```

### 3. Verificar el estado del servidor:
```bash
curl --cacert ./certs/ca.pem https://192.168.0.104:8443/healthz
# Respuesta esperada: {"status":"ok"}
```

---

## Paso 3: Configuración y Registro del Cliente Principal (Mac)

### 1. Exportar variables de entorno mTLS (en `~/.zshrc` o terminal):
```bash
export VLT_SYNC_CA_CERT="./certs/ca.pem"
export VLT_SYNC_CLIENT_CERT="./certs/client.pem"
export VLT_SYNC_CLIENT_KEY="./certs/client-key.pem"
```

### 2. Registrar el baúl con el servidor:
```bash
# Registra el baúl 'vault' generando UUID, api_key y sync_encryption_key:
./bin/vlt sync init --vault vault --server https://192.168.0.104:8443
```
*Salida esperada:*
```text
✅ Sync configured for vault: 2c450998-95db-4a5b-a5a1-47cdeb77b000
   Server: https://192.168.0.104:8443
   ✅ Registered with sync server
```

### 3. Subir los datos iniciales:
```bash
./bin/vlt sync push --vault vault
# Salida esperada: ✅ Pushed to server (seq 1)
```

---

## Paso 4: Conexión de un Segundo Dispositivo (PC Windows / VM Linux)

Para conectar un segundo cliente a la misma bóveda compartida:

### 1. Transferir los archivos necesarios al segundo cliente:
1. **Certificados mTLS**: `ca.pem`, `windows-pc.pem` y `windows-pc-key.pem`.
2. **Base de Datos SQLite**: Transferir la base completa incluyendo los archivos WAL si existen:
   ```bash
   scp ~/.config/passwd/vault.sqlite* usuario@192.168.0.104:~/.config/passwd/
   ```
   *(En Windows la ruta destino es `%APPDATA%\passwd\`)*.

### 2. Configurar en el segundo cliente:

* **En Windows (PowerShell)**:
  ```powershell
  $env:VLT_SYNC_CA_CERT = "C:\Users\tu_usuario\.config\passwd\certs\ca.pem"
  $env:VLT_SYNC_CLIENT_CERT = "C:\Users\tu_usuario\.config\passwd\certs\windows-pc.pem"
  $env:VLT_SYNC_CLIENT_KEY = "C:\Users\tu_usuario\.config\passwd\certs\windows-pc-key.pem"

  # Consultar secretos existentes
  .\bin\vlt.exe list

  # Agregar o modificar un secreto
  .\bin\vlt.exe add servidor-produccion --type password

  # Enviar los cambios al servidor
  .\bin\vlt.exe sync push
  ```

* **En Linux (Bash / Zsh)**:
  ```bash
  export VLT_SYNC_CA_CERT="/opt/vlt-sync/certs/ca.pem"
  export VLT_SYNC_CLIENT_CERT="/opt/vlt-sync/certs/client.pem"
  export VLT_SYNC_CLIENT_KEY="/opt/vlt-sync/certs/client-key.pem"

  vlt list
  vlt sync push
  ```

---

## Paso 5: Sincronización en Tiempo Real y Notificaciones de Escritorio

### A. En la Interfaz Gráfica (`vlt-gui`) 🖥️
Al abrir `./bin/vlt-gui`:
* El listener de Server-Sent Events (SSE) se conecta automáticamente en segundo plano.
* Cada vez que otro cliente sube un cambio (`sync push`), la GUI lo descarga sola, actualiza la lista de secretos en pantalla y lanza una notificación de escritorio.

### B. En la Terminal (`vlt sync listen`) ⌨️
Si trabajas sin GUI (Tmux, SSH, Neovim):
```bash
./bin/vlt sync listen --vault vault
```
Cuando un cliente remoto modifica un secreto, verás en consola:
```text
Listening for sync events from server...
✅ Synced with server (seq 2)
```

**Notificaciones de Escritorio Nativas**:
* **macOS**:
  ```text
  vlt — Bóveda sincronizada
  Cambios remotos aplicados (secuencia 2)
  ```
* **Windows**: Notificación Toast de Windows 10/11 en la esquina inferior derecha.
* **Linux**: Notificación gráfica vía `notify-send`.

---

## Paso 6: Gestión Multi-Bóveda (`vault` y `work`)

El sistema soporta múltiples bóvedas completamente aisladas. Cada bóveda tiene su propio UUID de sincronización y su canal independiente en el servidor:

```bash
# Sincronizar el baúl principal
./bin/vlt sync push --vault vault
./bin/vlt sync pull --vault vault

# Sincronizar una bóveda secundaria (ej. trabajo / equipos)
./bin/vlt sync init --vault work --server https://192.168.0.104:8443
./bin/vlt sync push --vault work
./bin/vlt sync pull --vault work

# En la GUI (vlt-gui)
Cambia de bóveda desde el selector 'VAULT' en el sidebar superior izquierdo y usa Settings > 'Save & Sync'.
```

### Auto-Recuperación y Resiliencia Multi-Bóveda
Si en `config.json` una bóveda activa es eliminada o renombrada en el disco, tanto la CLI como la GUI detectan la ausencia automáticamente y **hacen fallback transparente** a `vault.sqlite` o a `work.sqlite` sin bloquearse ni mostrar errores fatales.

---

## Paso 7: Guía de Solución de Problemas (Troubleshooting)

| Error Observado | Causa Raíz | Solución |
| :--- | :--- | :--- |
| `x509: certificate signed by unknown authority` | El cliente no está usando `ca.pem` o el servidor tiene un certificado viejo no firmado por la CA actual. | Asegurar `export VLT_SYNC_CA_CERT=./certs/ca.pem` en el cliente y reiniciar el contenedor con `server.pem`. |
| `x509: “vlt-sync Server” certificate is not standards compliant` | En macOS, el certificado tenía vigencia > 398 días o `KeyUsage` erróneo. | Regenerar certificados con `vlt pki generate` (ajustado automáticamente a 365 días y `DigitalSignature`). |
| `sync not configured: config key "sync_server_url" not found` | Al copiar `vault.sqlite` a otra máquina, no se copiaron los archivos de diario WAL (`vault.sqlite-wal`). | Copiar siempre con comodín: `scp ~/.config/passwd/vault.sqlite* destino:~/.config/passwd/`. |
| `open .../client.pem: no such file or directory` | Las variables `VLT_SYNC_CLIENT_CERT` o `KEY` apuntan a una ruta donde no existen los archivos. | Copiar `client.pem` y `client-key.pem` a la ruta indicada en la variable. |
| `Server registration failed — server may be unreachable` | El puerto 8443 no está abierto en el firewall o el contenedor no está corriendo. | Verificar con `curl -k https://IP:8443/healthz` y revisar `docker compose logs`. |
