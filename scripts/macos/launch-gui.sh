#!/bin/bash
# =============================================================================
# launch-gui.sh — Lanzador de vlt-gui en modo ventana completa para macOS
# Abre el gestor de bóvedas de escritorio completo (3 columnas, auditoría, settings)
# =============================================================================

BIN_PATH="$(cd "$(dirname "$0")/../../bin" && pwd)/vlt-gui"

if [ ! -f "$BIN_PATH" ]; then
    echo "Error: no se encontró el binario vlt-gui en $BIN_PATH"
    exit 1
fi

# Ejecutar vlt-gui en modo ventana de escritorio completa
exec "$BIN_PATH" "$@"
