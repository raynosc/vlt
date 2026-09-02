#!/bin/bash
# =============================================================================
# start-sync-server.sh
# =============================================================================
# Inicia el servidor de sincronización vlt-sync con TLS.
#
# Uso:
#   ./scripts/sync/start-sync-server.sh [IP] [PUERTO]
#
# Ejemplo:
#   ./scripts/sync/start-sync-server.sh 192.168.0.104 8443
#
# Variables de entorno opcionales:
#   VLT_SYNC_DB_PATH  - Ruta a la base de datos (default: ~/.config/passwd/sync-server.db)
# =============================================================================

set -e

# IP y puerto del servidor
SERVER_IP="${1:-192.168.0.104}"
SERVER_PORT="${2:-8443}"

# Directorio de configuración
CONFIG_DIR="${HOME}/.config/passwd"

# Certificados
CERT_FILE="$CONFIG_DIR/sync-cert.pem"
KEY_FILE="$CONFIG_DIR/sync-key.pem"

# Base de datos del servidor
DB_PATH="${VLT_SYNC_DB_PATH:-$CONFIG_DIR/sync-server.db}"

# Verificar que existen los certificados
if [ ! -f "$CERT_FILE" ]; then
    echo "❌ Error: No se encontró $CERT_FILE"
    echo "   Ejecutá primero: ./scripts/sync/generate-certs.sh $SERVER_IP"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "❌ Error: No se encontró $KEY_FILE"
    echo "   Ejecutá primero: ./scripts/sync/generate-certs.sh $SERVER_IP"
    exit 1
fi

# Buscar el binario del servidor
if [ -f "./bin/vlt-sync-linux-amd64" ]; then
    VLT_SYNC="./bin/vlt-sync-linux-amd64"
elif [ -f "./bin/vlt-sync" ]; then
    VLT_SYNC="./bin/vlt-sync"
elif command -v vlt-sync &> /dev/null; then
    VLT_SYNC="vlt-sync"
else
    echo "❌ Error: No se encontró el binario vlt-sync"
    echo "   Compilalo con: make build-linux"
    exit 1
fi

echo "=== Iniciando servidor de sincronización ==="
echo "  Binario:     $VLT_SYNC"
echo "  Dirección:   $SERVER_IP:$SERVER_PORT"
echo "  Certificado: $CERT_FILE"
echo "  Base datos:  $DB_PATH"
echo ""

# Matar servidor anterior si existe
if [ -f /tmp/vlt-sync.pid ]; then
    OLD_PID=$(cat /tmp/vlt-sync.pid 2>/dev/null)
    if [ -n "$OLD_PID" ]; then
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
fi

# Configurar variables de entorno
export VLT_SYNC_TLS_CERT="$CERT_FILE"
export VLT_SYNC_TLS_KEY="$KEY_FILE"
export VLT_SYNC_ADDR=":$SERVER_PORT"
export VLT_SYNC_DB_PATH="$DB_PATH"

# Iniciar servidor en segundo plano
nohup "$VLT_SYNC" > /tmp/vlt-sync.log 2>&1 &
echo $! > /tmp/vlt-sync.pid

sleep 2

# Verificar que está corriendo
if ps -p $! > /dev/null 2>&1; then
    echo "✅ Servidor iniciado (PID: $!)"
    echo "   Log: /tmp/vlt-sync.log"
    echo "   PID: /tmp/vlt-sync.pid"
    echo ""
    echo "=== Verificación ==="
    if command -v curl &> /dev/null; then
        curl --cacert "$CERT_FILE" -s "https://localhost:$SERVER_PORT/healthz" || echo "   ⚠️  No se pudo verificar (curl no disponible o error)"
    else
        echo "   Instalá curl para verificar: sudo apt install curl"
    fi
    echo ""
    echo "=== Para detener ==="
    echo "   kill \$(cat /tmp/vlt-sync.pid)"
else
    echo "❌ Error: El servidor no se pudo iniciar"
    echo "   Revisá el log: /tmp/vlt-sync.log"
    exit 1
fi
