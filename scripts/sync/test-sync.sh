#!/bin/bash
# =============================================================================
# test-sync.sh
# =============================================================================
# Prueba completa de sincronización entre dos vaults.
# Este script crea un vault, sube secretos al servidor, los baja en otro
# dispositivo y verifica que todo funciona correctamente.
#
# Uso:
#   PASSWD_MASTER_PASSWORD="tu-password" ./scripts/sync/test-sync.sh [IP] [PUERTO]
#
# Requisitos:
#   - Servidor vlt-sync corriendo (ver start-sync-server.sh)
#   - Certificado generado (ver generate-certs.sh)
#   - Variable PASSWD_MASTER_PASSWORD definida
# =============================================================================

set -e

# IP y puerto del servidor
SERVER_IP="${1:-192.168.0.104}"
SERVER_PORT="${2:-8443}"
SERVER_URL="https://${SERVER_IP}:${SERVER_PORT}"

# Verificar que PASSWD_MASTER_PASSWORD está definida
if [ -z "$PASSWD_MASTER_PASSWORD" ]; then
    echo "❌ Error: Definí la variable PASSWD_MASTER_PASSWORD"
    echo "   Ejemplo: PASSWD_MASTER_PASSWORD='mi-password' ./scripts/sync/test-sync.sh"
    exit 1
fi

# Directorio de configuración
CONFIG_DIR="${HOME}/.config/passwd"
CERT_FILE="$CONFIG_DIR/sync-cert.pem"

# Verificar certificado
if [ ! -f "$CERT_FILE" ]; then
    echo "❌ Error: No se encontró $CERT_FILE"
    echo "   Ejecutá primero: ./scripts/sync/generate-certs.sh $SERVER_IP"
    exit 1
fi

# Exportar certificado para que el cliente confíe en el servidor
export SSL_CERT_FILE="$CERT_FILE"

# Buscar el binario del cliente
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

# Archivos temporales
VAULT1="/tmp/vlt-sync-test-vault1.sqlite"
VAULT2="/tmp/vlt-sync-test-vault2.sqlite"

echo "=== Prueba de sincronización vlt ==="
echo "  Servidor:    $SERVER_URL"
echo "  Cliente:     $VLT"
echo "  Vault1:      $VAULT1"
echo "  Vault2:      $VAULT2"
echo ""

# Limpiar vaults anteriores
rm -f "$VAULT1" "$VAULT2"

# ============================================================================
# PASO 1: Crear vault1
# ============================================================================
echo "=== 1. Creando vault en dispositivo A ==="
$VLT init --vault-path "$VAULT1" --no-keychain 2>&1 | tail -3
echo ""

# ============================================================================
# PASO 2: Agregar secretos
# ============================================================================
echo "=== 2. Agregando secretos de prueba ==="
echo 'github-token-abc123' | $VLT add github --stdin --vault-path "$VAULT1" --no-keychain 2>&1 | grep -E 'stored|WARNING' | tail -1
echo 'aws-api-key-xyz789' | $VLT add aws --stdin --vault-path "$VAULT1" --no-keychain 2>&1 | grep -E 'stored|WARNING' | tail -1
echo '"

# ============================================================================
# PASO 3: Configurar sincronización en vault1
# ============================================================================
echo "=== 3. Configurando sincronización ==="
$VLT sync init --server "$SERVER_URL" --vault-path "$VAULT1" 2>&1

# ============================================================================
# PASO 4: Push (subir al servidor)
# ============================================================================
echo ""
echo "=== 4. Subiendo vault al servidor ==="
$VLT sync push --vault-path "$VAULT1" 2>&1 | tail -3

# ============================================================================
# PASO 5: Simular dispositivo B (copiar vault)
# ============================================================================
echo ""
echo "=== 5. Copiando vault a dispositivo B ==="
cp "$VAULT1" "$VAULT2"
echo "✅ Vault copiado"

# ============================================================================
# PASO 6: Verificar que vault2 tiene los mismos secretos
# ============================================================================
echo ""
echo "=== 6. Secretos en dispositivo B (antes del pull) ==="
$VLT list --vault-path "$VAULT2" --no-keychain 2>&1 | tail -5

# ============================================================================
# PASO 7: Agregar nuevo secreto en vault1
# ============================================================================
echo ""
echo "=== 7. Agregando nuevo secreto en dispositivo A ==="
echo 'new-secret-value' | $VLT add new-secret --stdin --vault-path "$VAULT1" --no-keychain 2>&1 | tail -1

# ============================================================================
# PASO 8: Push desde vault1
# ============================================================================
echo ""
echo "=== 8. Subiendo cambios desde dispositivo A ==="
$VLT sync push --vault-path "$VAULT1" 2>&1 | tail -3

# ============================================================================
# PASO 9: Pull en vault2
# ============================================================================
echo ""
echo "=== 9. Descargando cambios en dispositivo B ==="
$VLT sync pull --vault-path "$VAULT2" 2>&1 | tail -3

# ============================================================================
# PASO 10: Verificar sincronización
# ============================================================================
echo ""
echo "=== 10. Verificando sincronización ==="
echo ""
echo "--- Dispositivo A ---"
$VLT list --vault-path "$VAULT1" --no-keychain 2>&1 | tail -6

echo ""
echo "--- Dispositivo B ---"
$VLT list --vault-path "$VAULT2" --no-keychain 2>&1 | tail -6

# Verificar que el nuevo secreto está descifrado correctamente
echo ""
echo "=== 11. Verificando descifrado ==="
VALUE=$($VLT get new-secret --vault-path "$VAULT2" --no-keychain 2>&1 | grep -v "WARNING")
if [ "$VALUE" = "new-secret-value" ]; then
    echo "✅ Sincronización exitosa!"
    echo "   El secreto 'new-secret' se sincronizó y descifró correctamente."
else
    echo "❌ Error: El secreto no coincide"
    echo "   Esperado: new-secret-value"
    echo "   Obtenido: $VALUE"
    exit 1
fi

# ============================================================================
# Limpieza
# ============================================================================
echo ""
echo "=== Limpieza ==="
rm -f "$VAULT1" "$VAULT2"
echo "✅ Vaults de prueba eliminados"
echo ""
echo "=== Prueba completada exitosamente ==="
