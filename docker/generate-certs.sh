#!/usr/bin/env bash
# ThreatClaw — Generate TLS certificates for the reverse proxy
#
# Usage: ./generate-certs.sh [hostname]
#   hostname: "threatclaw.local" (default) or custom like "soc.entreprise.fr"
#
# Generates:
#   certs/ca.crt          — ThreatClaw CA root (install in browser for green padlock)
#   certs/ca.key          — CA private key (keep secret)
#   certs/server.crt      — Server certificate (used by nginx)
#   certs/server.key      — Server private key (used by nginx)

set -euo pipefail

CERT_DIR="${CERT_DIR:-$(dirname "$0")/certs}"
HOSTNAME="${1:-threatclaw.local}"

# Detect server IP
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo "[certs] Generating TLS certificates for: ${HOSTNAME}"
echo "[certs] Server IP detected: ${SERVER_IP}"

mkdir -p "${CERT_DIR}"

# Skip if certs already exist
if [ -f "${CERT_DIR}/server.crt" ] && [ -f "${CERT_DIR}/server.key" ]; then
    echo "[certs] Certificates already exist in ${CERT_DIR}/ — skipping"
    echo "[certs] To regenerate, delete ${CERT_DIR}/ and re-run"
    exit 0
fi

# ── Step 1: Generate CA ──
echo "[certs] Creating ThreatClaw CA..."
openssl ecparam -genkey -name prime256v1 -noout -out "${CERT_DIR}/ca.key" 2>/dev/null
openssl req -new -x509 -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
    -days 3650 -subj "/CN=ThreatClaw CA/O=ThreatClaw" 2>/dev/null

# ── Step 2: Generate server cert signed by CA ──
echo "[certs] Creating server certificate for ${HOSTNAME}..."
openssl ecparam -genkey -name prime256v1 -noout -out "${CERT_DIR}/server.key" 2>/dev/null
openssl req -new -key "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" \
    -subj "/CN=${HOSTNAME}/O=ThreatClaw" 2>/dev/null

# SAN: hostname + localhost + server IP → no warning regardless of access method
cat > "${CERT_DIR}/san.cnf" <<EOF
[v3_req]
subjectAltName = DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1,IP:${SERVER_IP}
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
    -out "${CERT_DIR}/server.crt" -days 3650 \
    -extfile "${CERT_DIR}/san.cnf" -extensions v3_req 2>/dev/null

# Cleanup temp files
rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/san.cnf" "${CERT_DIR}/ca.srl"

# Restrict permissions
chmod 600 "${CERT_DIR}/ca.key" "${CERT_DIR}/server.key"
chmod 644 "${CERT_DIR}/ca.crt" "${CERT_DIR}/server.crt"

echo ""
echo "[certs] ✅ Certificates generated in ${CERT_DIR}/"
echo ""
echo "  Server cert : ${CERT_DIR}/server.crt"
echo "  Server key  : ${CERT_DIR}/server.key"
echo "  CA root     : ${CERT_DIR}/ca.crt"
echo ""
echo "  Dashboard   : https://${HOSTNAME}"
echo ""
echo "  To get the green padlock, install the CA in your browser:"
echo "    - Chrome  : Settings > Privacy > Manage certificates > Authorities > Import ca.crt"
echo "    - Firefox : Settings > Privacy > View Certificates > Authorities > Import ca.crt"
echo "    - macOS   : sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt"
echo "    - Linux   : sudo cp ca.crt /usr/local/share/ca-certificates/threatclaw-ca.crt && sudo update-ca-certificates"
echo ""
