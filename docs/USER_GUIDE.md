# Guía de Usuario de vlt

`vlt` es un gestor de secretos local-first y zero-knowledge para desarrolladores. Esta guía te llevará desde la instalación hasta el uso avanzado de todas sus interfaces.

## Tabla de Contenidos

1.  [Instalación](#instalación)
2.  [Primeros Pasos](#primeros-pasos)
3.  [Conceptos Clave](#conceptos-clave)
4.  [Uso de la CLI (`vlt`)](#uso-de-la-cli-vlt)
5.  [Uso de la GUI (`vlt-gui`)](#uso-de-la-gui-vlt-gui)
6.  [Uso de la TUI (`vlt-tui`)](#uso-de-la-tui-vlt-tui)
7.  [Sincronización](#sincronización)
8.  [Resolución de Problemas](#resolución-de-problemas)

---

## Instalación

### Opción 1: Binarios Pre-compilados

Descarga los binarios desde la página de releases del repositorio de GitHub y colócalos en tu `PATH`.

### Opción 2: Con `go install`

Si tienes Go 1.26+ instalado:

```bash
go install github.com/raynosc/vlt/cmd/vlt@latest
go install github.com/raynosc/vlt/cmd/vlt-gui@latest
go install github.com/raynosc/vlt/cmd/vlt-tui@latest
```

### Opción 3: Compilar desde el Código Fuente

```bash
git clone https://github.com/raynosc/vlt.git
cd vlt
make build
```

Esto generará los binarios en el directorio `bin/`.

---

## Primeros Pasos

### 1. Inicializar el Vault

La primera vez que uses `vlt`, necesitas inicializar tu vault:

```bash
./bin/vlt init
```

Se te pedirá que crees una **contraseña maestra** segura. Esta contraseña es la única clave para acceder a todos tus secretos. **NO la olvides.**

### 2. Desbloquear el Vault

Cada vez que uses `vlt`, se te pedirá la contraseña maestra para desbloquear el vault. También puedes usar la variable de entorno `PASSWD_MASTER_PASSWORD` para scripts (con precaución).

### 3. Almacenar tu Primer Secreto

```bash
./bin/vlt add mi-token-github --value "ghp_xxxxxxxxxxxx"
./bin/vlt list
```

---

## Conceptos Clave

*   **Contraseña Maestra (Master Password):** La contraseña que protege todo tu vault. Deriva la clave de encriptación real (Argon2id) y nunca se almacena en disco.
*   **Vault:** Archivo SQLite encriptado (`vault.sqlite`) que almacena todos tus secretos. Ubicación: `~/.config/passwd/` (Linux), `~/Library/Application Support/passwd/` (macOS).
*   **Secreto (Secret):** Unidad básica de almacenamiento. Cada secreto tiene un nombre, un valor (encriptado), y metadatos (tipo, etiquetas, notas).
*   **Encriptación Zero-Knowledge:** El valor de cada secreto se encripta individualmente con AES-256-GCM. La desencriptación ocurre solo en tu dispositivo, con tu contraseña maestra.

---

## Uso de la CLI (`vlt`)

`vlt` es la interfaz de línea de comandos principal. Ejecuta `./bin/vlt` o `vlt` (si está en tu PATH).

### Añadir Secretos

*   **Interactivo:**
    ```bash
    vlt add mi-secreto
    # Se te pedirán: Nombre, Valor, Notas (opcional)
    ```

*   **No interactivo (scripts / CI):** el valor se lee por `stdin`, nunca como argumento (así no queda en el historial ni en la lista de procesos).
    ```bash
    echo "sk-xxx" | vlt add mi-api-key --stdin --type api_key
    ```

*   **Con metadatos:**
    ```bash
    vlt add github --type password --tags "trabajo,git" --notes "cuenta de la empresa"
    ```

*   **Desde un archivo (certificado, clave SSH):** auto-detecta el formato; si omitís el nombre, usa el del archivo.
    ```bash
    vlt add --file cert.pem
    vlt add --file ~/.ssh/id_ed25519
    # Para PKCS#12 (bundle .p12) con contraseña de descifrado:
    vlt add --file bundle.p12 --password p12pass
    ```

**Flags de `add`:** `--type` (`password`, `api_key`, `certificate`, `ssh_key`, `note`, `other`) · `--tags` (separadas por coma) · `--notes` · `--stdin` · `--file` · `--password` (solo con `--file`) · `--overwrite`.

### Listar y Buscar Secretos

```bash
# Listar todos los secretos
vlt list

# Filtrar por tipo (valores: password, api_key, certificate, ssh_key, note, other)
vlt list --kind certificate
vlt list --kind password
vlt list --kind ssh_key

# Filtrar por etiqueta, o listar todas las etiquetas con su conteo
vlt list --tag production
vlt list --tags

# Buscar por nombre
vlt search github

# Listar secretos próximos a expirar (en días)
vlt list --expiring 30
```

### Obtener y Mostrar Secretos

```bash
# Mostrar el valor del secreto
vlt get mi-secreto

# Copiar al portapapeles (se auto-borra a los 30s, solo si no copiaste otra cosa)
vlt get mi-secreto --copy

# Mostrar el secreto en JSON
vlt get mi-secreto --json
```

### Editar y Eliminar Secretos

```bash
# Editar interactivamente
vlt edit mi-secreto

# Eliminar
vlt rm mi-secreto
```

### Generar Contraseñas Seguras

```bash
# Generar una contraseña aleatoria (24 caracteres por defecto)
vlt generate

# Opciones:
vlt generate --length 32        # o -l 32
vlt generate --no-symbols       # excluir símbolos
vlt generate --copy             # copiar al portapapeles en vez de imprimir (o -c)
```

### Importar y Exportar

#### Importar

`vlt import <archivo>` detecta el formato por **la extensión** del archivo:

```bash
# CSV o JSON (esquema de exportación estándar: cada registro necesita nombre + password)
vlt import passwords.csv
vlt import data.json

# Validar el archivo SIN guardar nada (recomendado antes de importar de verdad)
vlt import passwords.csv --dry-run

# Reemplazar secretos existentes con el mismo nombre
vlt import passwords.csv --overwrite

# Importar un TOTP desde una imagen de código QR (otpauth://)
vlt import qr-code.png --qr
```

> Solo se aceptan extensiones `.csv` y `.json` (o una imagen con `--qr`). Cualquier otra extensión da error. Los registros sin nombre o sin password se omiten. El seed OTP se guarda cifrado dentro del valor del secreto, nunca en los metadatos en claro.

**Flags de `import`:** `--dry-run` · `--overwrite` · `--qr`.

#### Exportar

```bash
# Exportar todas las contraseñas a CSV o JSON
vlt export --format csv --force
vlt export --format json --force

# Exportar solo un tipo de secreto
vlt export --kind password --format json --force

# Exportar certificados/claves a archivos en un directorio
vlt export --kind certificate --output ./backup --force
```

**Flags de `export`:** `--format` (`csv` | `json`) · `--kind` (`password`, `api_key`, `certificate`, `ssh_key`, …; vacío = todos) · `--output` (directorio para certificados/claves) · `--force` (omite la confirmación; obligatorio en uso no interactivo).

> ⚠️ Un export pone tus secretos en **texto plano** en disco. Borralo apenas lo uses y nunca lo subas a un repositorio o backup sin cifrar.

### Múltiples Vaults (entornos en la misma máquina)

Si querés separar secretos por contexto —por ejemplo `trabajo`, `personal`, `cliente-X`— podés tener **varios vaults independientes** en la misma máquina. Cada uno es un archivo SQLite separado con su propia contraseña maestra.

```bash
# Listar los vaults disponibles y ver cuál está activo
vlt vault list

# Crear un vault nuevo
vlt vault create trabajo

# Cambiar el vault activo (los comandos siguientes operan sobre él)
vlt vault switch trabajo

# Eliminar un vault
vlt vault remove cliente-X
```

> Cada vault se desbloquea con SU propia contraseña maestra y no comparte secretos con los demás. Para compartir un mismo conjunto de secretos entre **dispositivos distintos**, no uses vaults separados: usá la sincronización (ver más abajo).

### Inspección (Sin Almacenar)

Analiza un archivo sin guardarlo en el vault:

```bash
vlt inspect cert.pem
vlt inspect --json cert.pem
```

### Auditoría de Seguridad

Verifica la salud de tu vault:

```bash
vlt audit
```

### Bloqueo y Desbloqueo

*   **Bloquear (cerrar el vault / olvidar la sesión del daemon):**
    ```bash
    vlt lock
    ```

*   **Desbloquear:** no hay un comando aparte. El desbloqueo se solicita **automáticamente** la primera vez que un comando necesita acceder al vault (te pide la contraseña maestra, o usa Touch ID en la GUI de macOS).

### Variables de Entorno

*   `PASSWD_MASTER_PASSWORD`: Para scripts y CI.
    ```bash
    PASSWD_MASTER_PASSWORD=mi-pass vlt list
    ```
*   `--no-env`: Ignorar la variable de entorno por seguridad.

---

## Uso de la GUI (`vlt-gui`)

`vlt-gui` ofrece una interfaz gráfica nativa con Fyne.

### Iniciar la GUI

```bash
./bin/vlt-gui
# o
vlt-gui
```

### Desbloqueo

Al iniciar, se muestra una pantalla de desbloqueo. En macOS, puedes usar **Touch ID** para desbloquear sin escribir la contraseña maestra.

### Interfaz Principal

La interfaz se divide en tres columnas:

1.  **Barra Lateral Izquierda:** Lista de categorías de secretos (Todos, Contraseñas, Claves API, Certificados, SSH, Notas) y acceso a múltiples vaults (si los usas).
2.  **Columna Central:** Lista de secretos en la categoría seleccionada.
3.  **Panel Derecho:** Detalles del secreto seleccionado. Permite editar el nombre, usuario, URL, contraseña (con botón de mostrar/ocultar), TOTP (con contador), y notas.

### Añadir un Secreto

*   Haz clic en el botón **"+"** o usa el atajo de teclado.
*   Selecciona el tipo de secreto (Contraseña, Clave API, Certificado, SSH, Nota).
*   Rellena los campos. Puedes generar una contraseña segura con el botón del dado (🎲).

### Watchtower

Accede al dashboard de seguridad desde el icono de "escudo" en la barra lateral. Identifica:
*   Contraseñas débiles o duplicadas.
*   Secretos sin TOTP habilitado.
*   Certificados próximos a expirar.

### Quick Access (`vlt-quick`)

Para un acceso ultra-rápido:
1.  Ejecuta `./bin/vlt-gui --quick` o activa el popup desde la bandeja del sistema.
2.  Vincula un atajo de teclado global (ej. `Shift+Cmd+K`) con herramientas como **macOS Shortcuts**, **Raycast** o **Alfred**.
3.  Escribe el nombre del secreto y presiona Enter para copiarlo al portapapeles.

### Preferencias

*   **Tema:** Oscuro (por defecto).
*   **Auto-lock:** Configurable (tiempo de inactividad antes de bloquear).

---

## Uso de la TUI (`vlt-tui`)

`vlt-tui` es una interfaz de usuario en terminal interactiva para quienes prefieren trabajar desde la línea de comandos sin salir de la terminal.

### Iniciar la TUI

```bash
./bin/vlt-tui
```

### Navegación

*   Usa las **flechas** para navegar por la lista de secretos.
*   Presiona **Enter** para ver los detalles del secreto seleccionado.
*   Presiona **Tab** para cambiar entre paneles.
*   Presiona **Esc** para volver o cerrar diálogos.

### Acciones

*   **a**: Añadir un nuevo secreto.
*   **e**: Editar el secreto seleccionado.
*   **d**: Eliminar el secreto seleccionado.
*   **Ctrl+f**: Buscar secretos.
*   **Ctrl+l**: Bloquear el vault.
*   **q**: Salir de la TUI.

---

## Sincronización (múltiples entornos)

`vlt` sincroniza el mismo vault entre varios dispositivos de forma **zero-knowledge** contra un servidor `vlt-sync` auto-hosteable.

### Conceptos

*   **Servidor `vlt-sync`:** servidor auto-hosteable que solo almacena un **blob cifrado** por vault. Nunca ve tus secretos en texto plano.
*   **`sync_encryption_key`:** clave AES-256 que cifra el blob. Se genera en tu dispositivo durante `sync init` y se guarda **dentro de tu vault**, envuelta con tu contraseña maestra.
*   **API key:** se genera en el cliente durante `sync init` (el servidor solo guarda su hash SHA-256). Sirve para autenticar tus `push`/`pull`.
*   **Modelo de confianza:** el cliente no confía en el servidor. Un servidor malicioso no puede leer tus secretos, ni resucitar uno borrado (tombstones), ni hacerte retroceder a un estado viejo (chequeo de secuencia monotónica).

### Quick path

```bash
# 1. (Una vez) Configurar la sincronización en el PRIMER dispositivo
vlt sync init --server https://tu-servidor.com

# 2. Subir el estado local al servidor
vlt sync push

# 3. En otro momento / dispositivo, traer los cambios
vlt sync pull

# 4. Ver el estado de sincronización
vlt sync status
```

> Para HTTP sin TLS (solo redes de confianza / pruebas) agregá `--insecure`. En producción usá siempre `https://`.

### Configurar un segundo dispositivo (mismo vault)

La `sync_encryption_key` y la API key viven **dentro del archivo del vault**. Por eso, para sincronizar el **mismo** conjunto de secretos en otra máquina, **no** corras `vlt init` ni `sync init` de nuevo (eso crearía un vault distinto y el `sync init` repetido es rechazado por el servidor). En su lugar:

1.  Copiá el archivo del vault (`*.sqlite`) del primer dispositivo al segundo, a la misma ruta de config (ver [Conceptos Clave](#conceptos-clave)). Por ejemplo con `scp`.
2.  En el segundo dispositivo, desbloqueá con la **misma contraseña maestra** y traé los cambios:
    ```bash
    vlt sync pull
    ```
3.  A partir de ahí, ambos dispositivos comparten el vault: `push` para subir, `pull` para bajar.

> El vault copiado ya contiene `vault_uuid`, `sync_encryption_key` y la API key (todo cifrado con tu master key), así que el segundo dispositivo queda listo sin re-registrar nada.

### Recuperar la API key

```bash
vlt sync show-key
```

### Referencia de comandos

| Comando | Qué hace |
|---|---|
| `vlt sync init --server <url>` | Genera el UUID del vault, la `sync_encryption_key` y la API key; registra el vault en el servidor. |
| `vlt sync push` | Cifra el vault y lo sube (concurrencia optimista por número de secuencia). |
| `vlt sync pull` | Baja el blob, verifica integridad y secuencia, y fusiona (last-writer-wins con tombstones). |
| `vlt sync status` | Muestra el estado de sincronización (acepta `--json`). |
| `vlt sync show-key` | Revela la API key almacenada. |

Para desplegar el servidor (Docker, TLS/Caddy, certificados) consultá [docs/SYNC.md](SYNC.md), [docs/SYNC-FLOW.md](SYNC-FLOW.md) y [docs/TLS-CERTIFICATES.md](TLS-CERTIFICATES.md).

---

## Resolución de Problemas

### El vault no se desbloquea

*   ¿Olvidaste la contraseña maestra?
    *   Si tienes un **Kit de Recuperación** (24 palabras), úsalo para restaurar el acceso.
    *   Si no, el vault es irrecuperable. **Nunca almacenamos la contraseña.**
*   ¿Estás usando la variable `PASSWD_MASTER_PASSWORD` y `--no-env` al mismo tiempo?

### `vlt-gui` no muestra Touch ID

*   Asegúrate de que el binario esté **firmado (code signed)**. En macOS, Touch ID requiere Entitlements específicos que se aplican con la firma de código.
*   Comprueba que el Keychain tenga la entrada correcta.

### Error al importar

*   **"unsupported file format":** `import` solo acepta archivos `.csv` o `.json` (o una imagen con `--qr`). Renombrá o convertí el archivo.
*   **Registros omitidos:** cada registro necesita al menos un nombre y un password; los que no los tienen se descartan. Corré primero `vlt import archivo.csv --dry-run` para ver qué se importaría sin guardar nada.

### Sincronización falla

*   ¿El servidor `vlt-sync` está corriendo y es accesible en la URL configurada?
*   **"rollback detected":** el servidor devolvió un estado más viejo que el local. Es una protección anti-retroceso; revisá que apuntes al servidor correcto y que no haya un blob desactualizado.
*   **Conflicto de secuencia (409):** alguien subió cambios antes que vos. `push` hace un `pull` automático y reintenta una vez; si vuelve a fallar, corré `vlt sync pull` manualmente y volvé a intentar.
*   **Segundo dispositivo no ve los secretos:** asegurate de haber **copiado el archivo del vault** (no de haber corrido `sync init` de nuevo) y de desbloquear con la misma contraseña maestra.

### Comandos de Diagnóstico

*   **Versión:**
    ```bash
    vlt version
    ```
*   **Verificar estado del vault:**
    ```bash
    vlt check
    ```
*   **Linting y pruebas:**
    ```bash
    make lint
    make test
    ```
