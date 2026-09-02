#!/bin/bash
# =============================================================================
# launch-quick.sh — Lanzador de vlt-gui en modo Quick Access para macOS
# Abre la ventana flotante nativa de búsqueda rápida
# =============================================================================

BIN_PATH="$(cd "$(dirname "$0")/../../bin" && pwd)/vlt-gui"

if [ ! -f "$BIN_PATH" ]; then
    echo "Error: no se encontró el binario vlt-gui en $BIN_PATH"
    exit 1
fi

# Ejecutar vlt-gui en modo quick nativo
exec "$BIN_PATH" -quick "$@"
