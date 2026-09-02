# Guía de Cliente y Sincronización para Windows

[English](../WINDOWS-CLIENT-GUIDE.md) | [Español](WINDOWS-CLIENT-GUIDE.md)

Esta guía detalla cómo compilar, configurar y operar el cliente **`vlt` en sistemas operativos Windows (10/11)**, permitiendo compartir y sincronizar bóvedas de forma segura con clientes macOS y Linux utilizando autenticación mutua mTLS y notificaciones nativas Toast.

---

## 1. Binarios Disponibles para Windows

El proyecto utiliza SQLite embebido en Go puro (`modernc.org/sqlite`) sin dependencias de CGo, permitiendo compilar binarios portables `.exe` de alto rendimiento.

| Binario | Propósito en Windows |
| :--- | :--- |
| **`vlt.exe`** | CLI para gestión de bóvedas (`add`, `get`, `edit`, `list`, `otp`, `audit`, `sync`). |
| **`vlt-gui.exe`** | Aplicación de escritorio nativa (Fyne GUI) con Watchtower, 3 columnas, instancia única IPC y bloqueo automático. |
| **`vlt-tui.exe`** | Terminal UI interactiva en Windows Terminal / PowerShell con cambio de bóveda (`Tab`). |
| **`vlt-quick.exe`** | Popup flotante para búsqueda instantánea y copia al portapapeles con auto-limpieza. |
| **`vlt-sync.exe`** | Servidor de sincronización (si se desea ejecutar en Windows). |

### Compilación desde macOS / Linux
En la raíz del proyecto, ejecuta:
```bash
make build-windows
```
Los binarios se generarán en la carpeta `bin/*.exe` (`vlt-gui.exe` compilado con MinGW-w64).

---

## 2. Emisión de Certificados mTLS para el Cliente Windows (en macOS/Admin)

En la máquina administradora donde reside la CA raíz (`ca.pem` y `ca-key.pem`), emite un certificado exclusivo para el usuario de Windows:

```bash
./bin/vlt pki client \
  --ca ./certs/ca.pem \
  --ca-key ./certs/ca-key.pem \
  --name "windows-pc" \
  --out ./certs
```

Esto generará:
* `windows-pc.pem` (Certificado público del cliente)
* `windows-pc-key.pem` (Clave privada del cliente)

---

## 3. Entrega de Archivos al Usuario de Windows

Transfiere de forma segura al equipo Windows:
1. Los binarios: `vlt.exe`, `vlt-tui.exe`, `vlt-quick.exe`.
2. Los certificados:
   * `ca.pem` (Certificado de la Autoridad Certificadora)
   * `windows-pc.pem` (Certificado del cliente)
   * `windows-pc-key.pem` (Clave privada del cliente)
3. La base de datos inicial:
   * El archivo `.sqlite` de la bóveda a compartir (ej. `vault.sqlite` o `work.sqlite`).

---

## 4. Configuración en Windows (PowerShell)

Abre PowerShell en Windows y sigue estos pasos:

### Paso 1: Crear directorios y ubicar archivos
```powershell
# Crear carpeta de configuración XDG en el perfil de Windows
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.config\passwd"
New-Item -ItemType Directory -Force -Path "C:\Tools\vlt\certs"

# Copiar la base de datos a la ruta estándar
Copy-Item ".\vault.sqlite" "$env:USERPROFILE\.config\passwd\vault.sqlite"

# Copiar certificados a la carpeta de herramientas
Copy-Item ".\ca.pem", ".\windows-pc.pem", ".\windows-pc-key.pem" "C:\Tools\vlt\certs\"

# Mover binarios a C:\Tools\vlt y agregarlos al PATH
Move-Item ".\vlt.exe", ".\vlt-tui.exe", ".\vlt-quick.exe" "C:\Tools\vlt\"
$env:Path += ";C:\Tools\vlt"
```

### Paso 2: Inicializar la sincronización mTLS
```powershell
.\vlt.exe sync init `
  --server "https://192.168.0.104:8443" `
  --tls-ca "C:\Tools\vlt\certs\ca.pem" `
  --tls-cert "C:\Tools\vlt\certs\windows-pc.pem" `
  --tls-key "C:\Tools\vlt\certs\windows-pc-key.pem"
```

### Paso 3: Probar la descarga inicial
```powershell
.\vlt.exe sync pull
```

---

## 5. Operación y Flujo de Trabajo en Windows

### A. Escucha en Tiempo Real (`sync listen`) y Notificaciones Toast
```powershell
.\vlt.exe sync listen
```
Cuando ocurra una modificación en otra máquina, `vlt` descargará los cambios automáticamente y disparará una **notificación Toast nativa de Windows**.

### B. Terminal UI interactiva (`vlt-tui.exe`)
```powershell
.\vlt-tui.exe
```
* **Selección de Bóveda**: Presiona **`Tab`** o **`←` / `→`** en la pantalla de desbloqueo para alternar entre bóvedas.
* **Navegación**: Códigos TOTP en vivo y copia segura al portapapeles.

### C. Búsqueda Rápida (`vlt-quick.exe`)
```powershell
.\vlt-quick.exe
```
* Escribe para filtrar en tiempo real.
* Presiona `Enter` para copiar la contraseña.
* **Auto-Limpieza**: Borrado automático del portapapeles tras 30 segundos.
