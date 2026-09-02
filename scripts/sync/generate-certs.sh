#!/bin/bash
# =============================================================================
# generate-certs.sh
# =============================================================================
# Genera certificados TLS con Subject Alternative Names (SANs) para el
# servidor de sincronización vlt-sync.
#
# Uso:
#   ./scripts/sync/generate-certs.sh [IP_DEL_SERVIDOR]
#
# Ejemplo:
#   ./scripts/sync/generate-certs.sh 192.168.0.104
#
# Si no se especifica IP, usa 192.168.0.104 por defecto.
# =============================================================================

set -e

# IP del servidor (por defecto: 192.168.0.104)
SERVER_IP="${1:-192.168.0.104}"

# Directorio donde guardar los certificados
CERT_DIR="${HOME}/.config/passwd"
mkdir -p "$CERT_DIR"

# Archivos de salida
KEY_FILE="$CERT_DIR/sync-key.pem"
CERT_FILE="$CERT_DIR/sync-cert.pem"
CONFIG_FILE="/tmp/openssl-san-${SERVER_IP}.cnf"

echo "=== Generando certificados TLS ==="
echo "  Servidor IP: $SERVER_IP"
echo "  Directorio:  $CERT_DIR"
echo ""

# Crear configuración de OpenSSL con SANs
cat > "$CONFIG_FILE" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $SERVER_IP

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth

[alt_names]
IP.1 = $SERVER_IP
DNS.1 = localhost
EOF

# Generar certificados (válidos por 365 días)
openssl req -x509 -nodes -days 365 \
  -newkey rsa:4096 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -config "$CONFIG_FILE" \
  2>&1

# Limpiar archivo temporal
rm -f "$CONFIG_FILE"

# Verificar permisos
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

# Mostrar resultado
echo ""
echo "=== Certificados generados ==="
echo "  Clave privada:  $KEY_FILE"
echo "  Certificado:    $CERT_FILE"
echo ""
echo "=== Verificación ==="
openssl x509 -in "$CERT_FILE" -text -noout | grep -A2 "Subject Alternative Name"
echo ""
echo "=== Siguiente paso ==="
echo "1. Copiá $CERT_FILE a todos los dispositivos clientes"
echo "2. Ejecutá: ./scripts/sync/start-sync-server.sh"
echo ""
echo "⚠️  IMPORTANTE: Guardá $KEY_FILE en un lugar seguro."
echo "   Nunca compartas la clave privada."
