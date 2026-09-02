#!/usr/bin/env bash
# =============================================================================
# uninstall-macos.sh — Desinstala vlt.app y sus binarios en macOS
# =============================================================================
set -e

echo "==> 1. Deteniendo procesos activos de vlt..."
killall vlt 2>/dev/null || true
killall vlt-gui 2>/dev/null || true

echo "==> 2. Eliminando /Applications/vlt.app..."
rm -rf "/Applications/vlt.app"

echo "==> 3. Eliminando binarios del CLI..."
rm -f "/usr/local/bin/vlt"
rm -f "$HOME/.local/bin/vlt"

# Preguntar o mostrar información sobre los datos de la bóveda
echo ""
echo "========================================================"
echo " ✅ vlt.app y sus binarios han sido desinstalados."
echo ""
echo " 🔒 NOTA DE PRIVACIDAD:"
echo "    Tus bóvedas cifradas y configuración NO fueron eliminadas."
echo "    Siguen seguras en: ~/.config/passwd/"
echo "    (Si deseas eliminar tus datos por completo: rm -rf ~/.config/passwd/)"
echo "========================================================"
