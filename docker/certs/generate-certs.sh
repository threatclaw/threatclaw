#!/usr/bin/env bash
# ThreatClaw — Generate mTLS certificates for inter-container communication.
# Self-signed CA + service certificates. Run once at first boot.
set -euo pipefail

CERT_DIR="${1:-.}"
DAYS=3650  # 10 years (internal only)
CA_SUBJ="/C=FR/O=ThreatClaw/CN=ThreatClaw Internal CA"

echo "╔══════════════════════════════════════╗"
echo "║  ThreatClaw — mTLS Certificate Gen   ║"
echo "╚══════════════════════════════════════╝"

mkdir -p "$CERT_DIR"

# ── 1. CA (Certificate Authority) ──
if [ ! -f "$CERT_DIR/ca.key" ]; then
  echo "[certs] Generating CA..."
  openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
  openssl req -new -x509 -days $DAYS -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" -subj "$CA_SUBJ" 2>/dev/null
  echo "[certs] CA created: ca.crt + ca.key"
else
  echo "[certs] CA already exists"
fi

# ── 2. Service certificates ──
SERVICES=("threatclaw-core" "threatclaw-dashboard" "threatclaw-db" "redis" "ollama")

for SVC in "${SERVICES[@]}"; do
  if [ ! -f "$CERT_DIR/${SVC}.crt" ]; then
    echo "[certs] Generating cert for ${SVC}..."

    # Generate key
    openssl genrsa -out "$CERT_DIR/${SVC}.key" 2048 2>/dev/null

    # Generate CSR with SAN
    cat > "$CERT_DIR/${SVC}.cnf" <<CNFEOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
C = FR
O = ThreatClaw
CN = ${SVC}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SVC}
DNS.2 = localhost
IP.1 = 127.0.0.1
CNFEOF

    openssl req -new -key "$CERT_DIR/${SVC}.key" \
      -out "$CERT_DIR/${SVC}.csr" -config "$CERT_DIR/${SVC}.cnf" 2>/dev/null

    # Sign with CA
    openssl x509 -req -days $DAYS \
      -in "$CERT_DIR/${SVC}.csr" \
      -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
      -out "$CERT_DIR/${SVC}.crt" \
      -extensions v3_req -extfile "$CERT_DIR/${SVC}.cnf" 2>/dev/null

    # Cleanup CSR and CNF
    rm -f "$CERT_DIR/${SVC}.csr" "$CERT_DIR/${SVC}.cnf"
    echo "[certs] ${SVC}: cert + key generated"
  else
    echo "[certs] ${SVC}: cert already exists"
  fi
done

echo ""
echo "Certificates generated in: $CERT_DIR"
echo "Files:"
ls -la "$CERT_DIR"/*.crt "$CERT_DIR"/*.key 2>/dev/null
echo ""
echo "To enable mTLS, mount these certs in docker-compose.yml"
echo "and set TC_MTLS_ENABLED=true"
