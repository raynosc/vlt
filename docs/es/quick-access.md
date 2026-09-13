# Quick Access — Ventana Flotante de Búsqueda Rápida

[English](../quick-access.md) | [Español](quick-access.md)

Quick Access proporciona una ventana flotante y compacta de búsqueda en tiempo real para encontrar y copiar valores de secretos al portapapeles de forma instantánea. Está integrada directamente en la aplicación de escritorio (`vlt-gui --quick`) y diseñada para vincularse a un atajo global de teclado (ej. `Shift+Cmd+K` o `Shift+Cmd+Space`).

## Uso

```bash
# Lanzar el popup de Quick Access:
vlt-gui --quick

# O mediante Makefile:
make run-quick

# Desde el bundle de macOS:
/Applications/vlt.app/Contents/MacOS/vlt --quick
```

## Atajos de Teclado

| Tecla | Acción |
|-------|--------|
| Escribir | Buscar secretos (filtrado en vivo) |
| ↑ / ↓ | Navegar entre los resultados |
| Enter | Copiar valor del secreto al portapapeles |
| Esc | Cerrar / cancelar el popup |

## Cómo Funciona

1. `vlt-gui --quick` se comunica a través de un socket IPC local ligero (`/tmp/vlt-gui.sock`). Si la interfaz gráfica ya está corriendo en segundo plano o en la bandeja del sistema (Systray), trae el popup flotante al frente de forma instantánea. Si no está en ejecución, se abre directamente en modo Quick Access.
2. Si la bóveda se encuentra bloqueada, el popup solicita la contraseña maestra directamente en la ventana compacta, sin necesidad de abrir la ventana principal de la aplicación.
3. Los secretos se cargan en una lista con filtrado instantáneo mientras escribes.
4. Al presionar **Enter**, se copia el secreto al portapapeles y se programa el borrado automático de seguridad mediante `vlt __clear-clipboard`.
5. La ventana se cierra automáticamente al copiar o al presionar **Esc**.

## Configuración de Atajo Global (macOS)

### Opción 1: Atajos de macOS (Recomendado)

1. Abre la aplicación **Atajos** (Shortcuts).
2. Crea un nuevo atajo con la acción **Ejecutar script de shell**:
   ```bash
   /usr/local/bin/vlt-gui --quick
   # o si usas el bundle .app:
   /Applications/vlt.app/Contents/MacOS/vlt --quick
   ```
3. En la pestaña de información (ⓘ), marca **Usar como acción rápida**.
4. Ve a **Ajustes del Sistema → Teclado → Atajos de teclado → Servicios**.
5. Ubica el atajo en **General** y asígnale `Shift+Cmd+K`.

### Opción 2: Raycast

1. Abre Raycast → **Extensions** → **Create Script Command**.
2. Nombre: `vlt Quick Access`.
3. Script:
   ```bash
   #!/bin/bash
   /usr/local/bin/vlt-gui --quick
   ```
4. Asigna el atajo `Shift+Cmd+K` en los ajustes de Raycast.

### Opción 3: Alfred

1. Abre Alfred → **Preferences** → **Workflows** → Crear nuevo workflow.
2. Añade un disparador **Hotkey** (`Shift+Cmd+K`).
3. Añade una acción **Run Script**:
   ```bash
   /usr/local/bin/vlt-gui --quick
   ```
4. Configura el tipo de script como `/bin/bash` con `with input as argv`.

## Características de Seguridad

1. **Auto-Limpieza del Portapapeles**: Al copiar, se programa un proceso desacoplado que vacía el portapapeles tras 30 segundos.
2. **Sin Fuga en Argumentos**: El secreto viaja al subproceso de borrado a través de un pipe seguro (`stdin`), protegiéndolo de herramientas de inspección de procesos (`ps aux`).
3. **Desbloqueo Local sin Fugas**: El desbloqueo se realiza en memoria local y las claves se limpian con `crypto.Zeroize` inmediatamente tras su uso.
