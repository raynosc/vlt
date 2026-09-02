#!/usr/bin/env bash
# =============================================================================
# install-macos.sh — Instala vlt.app en /Applications y el CLI vlt en /usr/local/bin
# =============================================================================
set -e

DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$DIR"

echo "==> Empaquetando la versión más reciente de vlt.app..."
bash "$DIR/scripts/macos/package-app.sh"

echo "==> Instalando en /Applications/vlt.app..."
# Cerrar instancia previa si está corriendo
killall vlt 2>/dev/null || true

rm -rf "/Applications/vlt.app"
cp -R "$DIR/build/vlt.app" "/Applications/vlt.app"

# Instalar binario CLI opcional en /usr/local/bin si es accesible
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    cp "$DIR/bin/vlt" "/usr/local/bin/vlt"
    echo "==> CLI instalado en /usr/local/bin/vlt"
elif [ -d "$HOME/.local/bin" ]; then
    mkdir -p "$HOME/.local/bin"
    cp "$DIR/bin/vlt" "$HOME/.local/bin/vlt"
    echo "==> CLI instalado en $HOME/.local/bin/vlt"
fi

echo ""
echo "========================================================"
echo " ✅ Instalación completada con éxito."
echo " 🚀 vlt.app está disponible en tu carpeta de Aplicaciones"
echo "    y en Spotlight / Launchpad."
echo "========================================================"
