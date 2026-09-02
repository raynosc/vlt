#!/bin/bash
# =============================================================================
# setup-client.sh
# =============================================================================
# Configura un dispositivo cliente para sincronizar con el servidor.
# Este script asume que ya tenés un vault y querés activar la sincronización.
#
# Uso:
#   PASSWD_MASTER_PASSWORD="tu-password" \
#     ./scripts/sync/setup-client.sh --server https://IP:PUERTO \
#     --vault-path /ruta/al/vault.sqlite
#
# Opciones:
#   --server     URL del servidor de sincronización (requerido)
#   --vault-path Ruta al vault (default: ~/.config/passwd/default.sqlite)
#   --cert       Ruta al certificado (default: ~/.config/passwd/sync-cert.pem)
# =============================================================================

set -e

# Valores por defecto
CONFIG_DIR="${HOME}/.config/passwd"
VAULT_PATH="$CONFIG_DIR/default.sqlite"
CERT_FILE="$CONFIG_DIR/sync-cert.pem"
SERVER_URL=""

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --server)
            SERVER_URL="$2"
            shift 2
            ;;
        --vault-path)
            VAULT_PATH="$2"
            shift 2
            ;;
        --cert)
            CERT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Uso: $0 --server <url> [--vault-path <path>] [--cert <path>]"
            echo ""
            echo "Opciones:"
            echo "  --server      URL del servidor (ej: https://192.168.0.104:8443)"
            echo "  --vault-path  Ruta al archivo vault (default: ~/.config/passwd/default.sqlite)"
            echo "  --cert        Ruta al certificado (default: ~/.config/passwd/sync-cert.pem)"
            exit 0
            ;;
        *)
            echo "❌ Opción desconocida: $1"
            echo "Usá --help para ver las opciones"
            exit 1
            ;;
    esac
done

# Verificar requisitos
if [ -z "$SERVER_URL" ]; then
    echo "❌ Error: Tenés que especificar --server"
    echo "   Ejemplo: $0 --server https://192.168.0.104:8443"
    exit 1
fi

if [ -z "$PASSWD_MASTER_PASSWORD" ]; then
    echo "❌ Error: Definí la variable PASSWD_MASTER_PASSWORD"
    echo "   Ejemplo: PASSWD_MASTER_PASSWORD='mi-password' $0 --server ..."
    exit 1
fi

if [ ! -f "$CERT_FILE" ]; then
    echo "❌ Error: No se encontró el certificado: $CERT_FILE"
    echo "   Copiá el certificado desde el servidor o ejecutá generate-certs.sh"
    exit 1
fi

if [ ! -f "$VAULT_PATH" ]; then
    echo "❌ Error: No se encontró el vault: $VAULT_PATH"
    echo "   Creá uno con: vlt init"
    exit 1
fi

# Buscar el binario
if [ -f "./bin/vlt-linux-amd64" ]; then
    VLT="./bin/vlt-linux-amd64"
elif [ -f "./bin/vlt" ]; then
    VLT="./bin/vlt"
elif command -v vlt &> /dev/null; then
    VLT="vlt"
else
    echo "❌ Error: No se encontró el binario vlt"
    echo "   Compilalo con: make build-linux"
    exit 1
fi

# Exportar certificado
export SSL_CERT_FILE="$CERT_FILE"

echo "=== Configurando cliente de sincronización ==="
echo "  Vault:       $VAULT_PATH"
echo "  Servidor:    $SERVER_URL"
echo "  Certificado: $CERT_FILE"
echo ""

# Configurar sincronización
echo "=== 1. Inicializando sincronización ==="
$VLT sync init --server "$SERVER_URL" --vault-path "$VAULT_PATH" 2>&1

echo ""
echo "=== 2. Estado de sincronización ==="
$VLT sync status --vault-path "$VAULT_PATH" 2>&1

echo ""
echo "=== Configuración completada ==="
echo ""
echo "Comandos útiles:"
echo "  $VLT sync push --vault-path $VAULT_PATH     # Subir cambios"
echo "  $VLT sync pull --vault-path $VAULT_PATH     # Descargar cambios"
echo "  $VLT sync status --vault-path $VAULT_PATH   # Ver estado"
echo ""
echo "Tip: Agregá esto a tu ~/.bashrc o ~/.zshrc:"
echo "  export SSL_CERT_FILE=$CERT_FILE"
