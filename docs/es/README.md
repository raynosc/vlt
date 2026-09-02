# vlt — Gestor de Secretos Seguro

[English](../../README.md) | [Español](README.md)

Un gestor de contraseñas y secretos local-first y zero-knowledge para todo el mundo — desde usuarios particulares y equipos hasta desarrolladores. Almacena contraseñas, inicios de sesión, códigos 2FA/TOTP, claves de API, certificados TLS y claves SSH en una bóveda SQLite cifrada — con extracción enriquecida de metadatos, auditorías de seguridad Watchtower y una interfaz gráfica nativa moderna.

**Arquitectura**: el cifrado y descifrado ocurren exclusivamente en el cliente. La base de datos contiene únicamente texto cifrado e índices ciegos HMAC para los valores y metadatos de los secretos.

## Binarios

| Binario | Descripción |
|---------|-------------|
| `vlt` | CLI para todas las operaciones de la bóveda |
| `vlt-gui` | GUI nativa (Fyne) con diseño de 3 columnas, Watchtower y modo oscuro |
| `vlt-tui` | Terminal UI (Bubble Tea) interactiva para la consola |
| `vlt-quick` | Popup flotante de búsqueda rápida para copiar secretos al portapapeles |
| `vlt-sync` | Servidor de sincronización entre dispositivos (ver [Guía de Despliegue](SYNC-DEPLOYMENT.md)) |

## Inicio Rápido

```bash
# Compilar todos los binarios para la plataforma actual
make build

# Compilar para todas las plataformas (macOS, Linux amd64/arm64, Windows)
make build-all

# Ejecutar todos los tests unitarios
make test

# Inicializar una nueva bóveda (genera kit de recuperación de 24 palabras)
./bin/vlt init

# Almacenar secretos (solicita de forma segura el valor enmascarado — nunca en el historial bash)
./bin/vlt add github-token
./bin/vlt add api-key --type api_key

# Pasar el secreto por entrada estándar (stdin)
echo -n "mi-api-key" | ./bin/vlt add ci-token --stdin

# Importar certificados y claves SSH (auto-detecta formato y extrae metadatos)
./bin/vlt add --file cert.pem
./bin/vlt add --file ~/.ssh/id_ed25519
./bin/vlt add --file bundle.p12

# Importar desde otros gestores (Bitwarden, Apple Passwords, Chrome, KeePass, CSV, JSON)
./bin/vlt import passwords.csv

# Listar y buscar
./bin/vlt list
./bin/vlt list --kind certificate
./bin/vlt list --expiring 30
./bin/vlt search github

# Inspeccionar certificados sin guardarlos
./bin/vlt inspect cert.pem
./bin/vlt inspect --json cert.pem

# Obtener secretos
./bin/vlt get github-token

# Generar certificados mTLS Zero-Trust (CA, Servidor con SANs, Cliente)
./bin/vlt pki generate --out ./certs --hosts "192.168.0.104,localhost" --client "mac-laptop"

# Ejecutar la interfaz gráfica nativa
./bin/vlt-gui

# Ejecutar el popup flotante de Quick Access
./bin/vlt-quick

# Ejecutar la interfaz de terminal interactiva (TUI)
./bin/vlt-tui
```

## Targets del Makefile

```bash
# ── CI Local y Control de Calidad (Pre-Commit / Pre-Push) ─────────────────────
make check         # Ejecuta gofmt + go vet + golangci-lint + unit tests
make vuln          # Escanea vulnerabilidades con govulncheck
make ci            # Suite completa de CI: lint + vuln + tests con detector de carreras (-race)

# ── Tests ────────────────────────────────────────────────────────────────────
make test          # Ejecuta todos los tests unitarios
make test-all      # Ejecuta tests con detector de carreras de concurrencia (-race)
make test-cover    # Reporte de cobertura en HTML → coverage.html
make fuzz          # Pruebas de mutación continua (Fuzz testing)

# ── Compilación y Empaquetado ────────────────────────────────────────────────
make build         # Compila todos los binarios en bin/ para la plataforma actual
make app           # Empaqueta la aplicación nativa para macOS (build/vlt.app)
make install-mac   # Instala vlt.app en /Applications y el CLI en el PATH (/usr/local/bin/vlt)
make uninstall-mac # Desinstalación limpia (conserva tus bóvedas cifradas en ~/.config/passwd/)
make build-all     # Compila binarios para macOS, Linux y Windows
make build-linux   # Compila binarios para Linux (amd64 + arm64)
make build-windows # Compila binarios para Windows (.exe) incluyendo GUI
make clean         # Elimina bin/ y archivos temporales de cobertura

# ── Ejecución Local ──────────────────────────────────────────────────────────
make run-gui       # go run ./cmd/vlt-gui
make run-tui       # go run ./cmd/vlt-tui
make run-quick     # go run ./cmd/vlt-gui --quick
make run-cli       # CLI vlt
make help          # Muestra todos los comandos disponibles
```

## Seguridad

| Característica | Implementación |
|----------------|----------------|
| Derivación de clave | **Argon2id** (t=3, m=64MB, p=4) |
| Cifrado | **AES-256-GCM** con sobre independiente por secreto |
| Seguridad de metadatos | Metadatos cifrados zero-knowledge con índices ciegos HMAC |
| Verificación de contraseña | **Tiempo constante** con HKDF-SHA256 |
| Formato de bóveda | SQLite — cero texto en plano en disco |
| Zero-knowledge | Cifrado y descifrado únicamente en memoria RAM del cliente |
| Recuperación | Kit de recuperación mnemónico de 24 palabras BIP-39 |
| Seguridad en memoria | Los buffers sensibles se sobreescriben a cero inmediatamente (`Zeroize`) |

### Automatización No Interactiva

`PASSWD_MASTER_PASSWORD` permite el uso en scripts o pipelines CI.
Usa `--no-env` para deshabilitar la lectura de variables de entorno en entornos estrictos:

```bash
PASSWD_MASTER_PASSWORD=secret ./bin/vlt list
./bin/vlt --no-env list                      # ignora la variable de entorno, pide contraseña
```

## Ubicación de la Bóveda

```
macOS:   ~/.config/passwd/vault.sqlite (o ~/Library/Application Support/passwd/)
Linux:   ~/.config/passwd/vault.sqlite
Windows: %APPDATA%/passwd/vault.sqlite
```

Sobrescribe la ruta con `--vault-path <ruta>` o usa el selector multi-bóveda con `vlt vault switch <nombre>`.

## Formatos Soportados

| Formato | Extensiones | Notas |
|---------|-------------|-------|
| Exportación CSV | `.csv` | Auto-detecta `,`, `;`, `\t` (Bitwarden, Apple, Chrome, KeePass, etc.) |
| Exportación JSON | `.json` | Formato estándar de exportación JSON |
| Certificado X.509 | `.pem`, `.crt`, `.cer` | Extracción completa de metadatos (CN, emisor, SANs, expiración) |
| Clave Privada SSH | `id_rsa`, `id_ed25519`, `id_ecdsa` | Soporte para RSA, Ed25519 y ECDSA |
| Clave Pública SSH | `.pub` | Muestra tipo y huella digital (fingerprint) |
| Paquete PKCS#12 | `.p12`, `.pfx` | Paquetes protegidos con contraseña |
| TOTP / HOTP | URI OTPAuth en metadatos | Generación de códigos en vivo con cuenta regresiva |

## Características de la GUI (`vlt-gui` & `vlt-gui.exe`)

- **Diseño moderno en 3 columnas**: barra lateral (categorías + bóvedas) | lista de secretos | panel de detalle
- **Atajos Globales Nativos Sin Permisos (macOS)**: Atajos globales a nivel de sistema (`Shift+Cmd+Space` para Quick Access, `Shift+Cmd+V` para la Bóveda) impulsados por la API nativa Carbon `RegisterEventHotKey` (requiere **cero** permisos de Accesibilidad o Entrada)
- **Recarga Dinámica de Atajos**: Modifica las combinaciones en Configuración en cualquier momento con actualización en tiempo real en memoria
- **Icono Nítido Retina en Barra de Menú / Systray**: Icono monocromo en la barra de estado de macOS que mantiene la aplicación residente en segundo plano al cerrar ventanas
- **Instancia Única (Single-Instance IPC)**: Al abrir la app estando en ejecución, trae la ventana existente al frente sin demoras
- **Bloqueo Automático por Inactividad**: Temporizador configurable en Ajustes (`5m`, `15m`, `30m`, `60m`, `Nunca`)
- **Panel de Seguridad Watchtower**: Auditoría de contraseñas débiles, duplicados, ausencia de 2FA y certificados por expirar
- **Iconos por Tipo y Marcas Oficiales**: Contraseñas, API keys, certificados, SSH keys, notas y logos vectoriales SVG
- **Caché Local de Favicons en Disco**: Almacenamiento rápido en `~/.config/passwd/cache/favicons/` para desplazamiento fluido
- **Edición en Línea**: Modificación rápida de usuario, URL, notas, contraseña con botón de ocultar/mostrar y TOTP
- **Tema Oscuro y Densidad Optimizada**: Vista de lista compacta para visualizar múltiples registros en pantalla

## Empaquetado e Instalación Nativa en macOS

Puedes empaquetar e instalar `vlt` como una aplicación nativa de macOS (`vlt.app` con icono Retina `.icns` e integración con CLI):

```bash
# Empaquetar en build/vlt.app
make app

# Instalar en /Applications/vlt.app y CLI en el PATH (/usr/local/bin/vlt)
make install-mac

# Desinstalación limpia (conserva tus bóvedas cifradas en ~/.config/passwd/)
make uninstall-mac
```

## PKI mTLS Zero-Trust y Sincronización

`vlt` incluye un generador de PKI integrado para emitir certificados TLS mutuo (mTLS) con curvas elípticas ECDSA P-256:

```bash
# 1. Generar la jerarquía completa de PKI (CA, Servidor con SANs y Cliente):
./bin/vlt pki generate --out ./certs --hosts "192.168.0.104,localhost" --client "mac-laptop"

# 2. Emitir certificados de cliente adicionales (ej. para una PC con Windows):
./bin/vlt pki client --ca ./certs/ca.pem --ca-key ./certs/ca-key.pem --name "windows-pc" --out ./certs
```

**Archivos generados en `./certs/`**:
* `ca.pem` — Autoridad Certificadora Raíz (compartida con servidor y clientes).
* `ca-key.pem` — Clave privada de la CA (mantener segura/offline para emitir futuros clientes).
* `server.pem` y `server-key.pem` — Certificado TLS del servidor (con SANs IP/DNS) y clave privada.
* `client.pem` y `client-key.pem` — Certificado mTLS del cliente y clave privada.

## Documentación

- [Índice de Documentación en Español](README.md)
- [Diagramas de Arquitectura (Mermaid)](ARCHITECTURE-MERMAID.md) — Diagramas visuales completos del Core, PKI mTLS y Sincronización en Tiempo Real.
- [Arquitectura del Sistema](ARCHITECTURE.md) — Filosofía de diseño, capas internas, flujo de datos y modelo de seguridad.
- [Guía de Usuario](USER_GUIDE.md) — Guía completa de uso para CLI, GUI, TUI, instalación y resolución de problemas.
- [Guía de Cliente Windows y Sincronización](WINDOWS-CLIENT-GUIDE.md) — Configuración, compilación y sincronización en Windows.
- [Guía de Certificados TLS, PKI y mTLS](TLS-CERTIFICATES.md) — Generación de certificados, anatomía, SANs y mTLS.
- [Guía de Despliegue del Servidor de Sincronización](SYNC-DEPLOYMENT.md) — Docker, Compose, Kubernetes y operaciones TLS.
- [Guía de 2FA y TOTP](OTP-TOTP-GUIDE.md) — Qué es TOTP, ventajas de seguridad y uso.
- [Hoja de Ruta de Apps Móviles](MOBILE-ROADMAP.md) — Arquitectura móvil, puente Go mobile y biometría.
- [Referencia de API del Servidor Sync](SYNC_API.md) — Endpoints REST, autenticación y eventos SSE en tiempo real.
- [Guía de Quick Access](quick-access.md) — Configuración y uso del popup flotante.
- [Guía para Agentes de IA](../../AGENTS.md) — Mapa de paquetes, invariantes de seguridad y convenciones de calidad.

## Requisitos

- **Go 1.24+ / 1.26+**
- SQLite vía `modernc.org/sqlite` (Go puro, cero CGo requerido para CLI/Sync/TUI)
- `golang.org/x/crypto` (Argon2, HKDF, análisis de claves SSH)

## Instalación

```bash
go install github.com/raynosc/vlt/cmd/vlt@latest
go install github.com/raynosc/vlt/cmd/vlt-gui@latest
go install github.com/raynosc/vlt/cmd/vlt-tui@latest
go install github.com/raynosc/vlt/cmd/vlt-quick@latest
go install github.com/raynosc/vlt/cmd/vlt-sync@latest
```

O compilar desde el código fuente:

```bash
git clone https://github.com/raynosc/vlt.git
cd vlt
make build
```

## Licencia

MIT
