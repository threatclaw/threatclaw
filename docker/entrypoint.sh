#!/usr/bin/env bash
# ThreatClaw — Docker entrypoint
# Handles first-time setup, migrations, auth token, and background model pull.
set -euo pipefail

echo "╔══════════════════════════════════════════════════╗"
echo "║          ThreatClaw — Starting...                ║"
echo "╚══════════════════════════════════════════════════╝"

# ── Load secrets from Docker secret files (See ADR-039) ──
if [ -f /run/secrets/tc_db_password ]; then
  export POSTGRES_PASSWORD="$(cat /run/secrets/tc_db_password)"
  export TC_DB_PASSWORD="$POSTGRES_PASSWORD"
  echo "[init] DB password loaded from Docker secret"
elif [ -n "${TC_DB_PASSWORD:-}" ]; then
  export POSTGRES_PASSWORD="${TC_DB_PASSWORD}"
fi

if [ -f /run/secrets/tc_auth_token ]; then
  export GATEWAY_AUTH_TOKEN="$(cat /run/secrets/tc_auth_token)"
  echo "[init] Auth token loaded from Docker secret"
fi

# ── Security: reject default credentials ──
if [ "${POSTGRES_PASSWORD:-}" = "threatclaw" ] || [ -z "${POSTGRES_PASSWORD:-}" ]; then
    echo ""
    echo "[SECURITY] ════════════════════════════════════════════"
    echo "[SECURITY]  FATAL: Default database password detected!"
    echo "[SECURITY]  Set TC_DB_PASSWORD in .env or use Docker secrets."
    echo "[SECURITY]  ThreatClaw refuses to start with default credentials."
    echo "[SECURITY] ════════════════════════════════════════════"
    echo ""
    exit 1
fi

# ── Wait for PostgreSQL ──
# Use pg_isready if available (preferred: checks PG protocol readiness),
# otherwise fall back to a bash /dev/tcp TCP connect (works in any image).
echo "[init] Waiting for PostgreSQL..."
DB_HOST="${TC_DB_HOST:-threatclaw-db}"
DB_PORT="${TC_DB_PORT:-5432}"
DB_USER="${POSTGRES_USER:-threatclaw}"
for i in $(seq 1 60); do
  if command -v pg_isready >/dev/null 2>&1; then
    if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -q 2>/dev/null; then
      echo "[init] PostgreSQL ready (pg_isready)"
      break
    fi
  else
    # Fallback: bash /dev/tcp — works when postgresql-client isn't installed
    if timeout 1 bash -c ": </dev/tcp/$DB_HOST/$DB_PORT" 2>/dev/null; then
      echo "[init] PostgreSQL ready (tcp connect)"
      break
    fi
  fi
  if [ "$i" -eq 60 ]; then
    echo "[init] ERROR: PostgreSQL not reachable after 60s at $DB_HOST:$DB_PORT"
    exit 1
  fi
  sleep 1
done

# ── Inject DB password into DATABASE_URL (read from Docker secret) ──
if [ -n "${POSTGRES_PASSWORD:-}" ] && echo "${DATABASE_URL:-}" | grep -q '@'; then
  # Insert password into URL: postgres://user@host → postgres://user:pass@host
  export DATABASE_URL=$(echo "$DATABASE_URL" | sed "s|://\([^@]*\)@|://\1:${POSTGRES_PASSWORD}@|")
fi

# ── Trust our CA cert for PostgreSQL TLS (self-signed CA) ──
if [ -f /app/certs/ca.crt ]; then
  cp /app/certs/ca.crt /usr/local/share/ca-certificates/threatclaw-ca.crt 2>/dev/null || true
  update-ca-certificates 2>/dev/null || true
  export SSL_CERT_FILE=/app/certs/ca.crt
fi

# ── Setup .pgpass for secure DB access (no PGPASSWORD in env) ──
# Use the writable data volume (core-data mounted at /app/data)
echo "${TC_DB_HOST:-threatclaw-db}:${TC_DB_PORT:-5432}:${POSTGRES_DB:-threatclaw}:${POSTGRES_USER:-threatclaw}:${POSTGRES_PASSWORD}" > /app/data/.pgpass
chmod 600 /app/data/.pgpass
export PGPASSFILE=/app/data/.pgpass

# ── Ensure reports temp dir exists (for PDF export via Typst) ──
mkdir -p /app/data/reports

# ── Generate auth token if not provided ──
if [ -z "${GATEWAY_AUTH_TOKEN:-}" ]; then
  EXISTING_TOKEN=$(psql -h "${TC_DB_HOST:-threatclaw-db}" -U "${POSTGRES_USER:-threatclaw}" -d "${POSTGRES_DB:-threatclaw}" -tAc \
    "SELECT trim(both '\"' from value::text) FROM settings WHERE key = 'channels.gateway_auth_token' LIMIT 1" 2>/dev/null || echo "")

  if [ -n "$EXISTING_TOKEN" ] && [ "$EXISTING_TOKEN" != "" ]; then
    export GATEWAY_AUTH_TOKEN="$EXISTING_TOKEN"
    echo "[init] Auth token loaded from DB"
  else
    export GATEWAY_AUTH_TOKEN=$(openssl rand -hex 64)
    echo "[init] Auth token generated (new installation)"
  fi
fi

# ── Write token to shared volume for dashboard (secure permissions) ──
set +e
if [ -d "/shared" ]; then
  echo "TC_CORE_TOKEN=${GATEWAY_AUTH_TOKEN}" > /shared/.env.token 2>/dev/null
  chmod 600 /shared/.env.token 2>/dev/null
  [ $? -eq 0 ] && echo "[init] Token shared with dashboard (mode 0600)" || echo "[init] WARN: Token not shared — dashboard uses TC_AUTH_TOKEN from .env"
fi
set -e

# ── Ensure Fluent Bit staging trigger exists ──
echo "[init] Setting up log ingestion trigger..."
psql -h "${TC_DB_HOST:-threatclaw-db}" -U "${POSTGRES_USER:-threatclaw}" -d "${POSTGRES_DB:-threatclaw}" -q <<'TRIGGERSQL' 2>/dev/null || echo "[init] WARN: Could not create log trigger"
CREATE TABLE IF NOT EXISTS logs_fluentbit (tag TEXT, time TIMESTAMPTZ DEFAULT NOW(), data JSONB DEFAULT '{}');
CREATE OR REPLACE FUNCTION fn_fluentbit_to_logs() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO logs (tag, time, data, hostname, collector)
    VALUES (COALESCE(NEW.tag, 'unknown'), COALESCE(NEW.time, NOW()), COALESCE(NEW.data, '{}'::jsonb),
            COALESCE(NEW.data->>'hostname', NEW.data->>'host'), COALESCE(NEW.data->>'collector', 'fluent-bit'));
    RETURN NULL; -- Don't keep data in staging table
END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_fluentbit_ingest ON logs_fluentbit;
CREATE TRIGGER trg_fluentbit_ingest AFTER INSERT ON logs_fluentbit FOR EACH ROW EXECUTE FUNCTION fn_fluentbit_to_logs();
TRIGGERSQL
echo "[init] Log ingestion trigger ready"

# ── Pull Ollama models in BACKGROUND (non-blocking) ──
pull_models_background() {
  OLLAMA_URL="${OLLAMA_BASE_URL:-http://ollama:11434}"

  # Wait for Ollama (up to 2 min)
  echo "[models] Waiting for Ollama..."
  for i in $(seq 1 120); do
    if curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
      echo "[models] Ollama ready"
      break
    fi
    [ "$i" -eq 120 ] && echo "[models] WARNING: Ollama not reachable — skipping" && return
    sleep 1
  done

  MODELS=$(curl -s "${OLLAMA_URL}/api/tags" 2>/dev/null | python3 -c "import sys,json; print(' '.join(m['name'] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null || echo "")

  # ── threatclaw-primary (Foundation-Sec Q4_K_M) — fast cyber triage, sync L1
  PRIMARY_BASE="hf.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF"
  if ! echo "$MODELS" | grep -q "$PRIMARY_BASE"; then
    echo "[models] Downloading Primary model (Foundation-Sec Q4_K_M) — ~5 GB..."
    curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\":\"$PRIMARY_BASE\",\"stream\":false}" > /dev/null 2>&1
  fi
  if ! echo "$MODELS" | grep -q "threatclaw-primary"; then
    echo "[models] Creating threatclaw-primary..."
    curl -s -X POST "${OLLAMA_URL}/api/create" \
      -d "{\"name\":\"threatclaw-primary\",\"from\":\"$PRIMARY_BASE\",\"system\":\"You are ThreatClaw primary triage engine. Analyze security dossiers and return ONLY valid JSON. Never add commentary outside the JSON structure.\",\"parameters\":{\"temperature\":0.1,\"num_ctx\":4096,\"num_predict\":1024}}" --max-time 30 > /dev/null 2>&1
    echo "[models] threatclaw-primary ready"
  fi

  # ── threatclaw-forensic (Foundation-Sec Reasoning Q8_0) — deep async forensic enrichment
  FORENSIC_BASE="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF"
  if ! echo "$MODELS" | grep -q "$FORENSIC_BASE"; then
    echo "[models] Downloading Forensic model (Foundation-Sec Reasoning Q8_0) — ~8.5 GB..."
    curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\":\"$FORENSIC_BASE\",\"stream\":false}" > /dev/null 2>&1
  fi
  if ! echo "$MODELS" | grep -q "threatclaw-forensic"; then
    echo "[models] Creating threatclaw-forensic..."
    curl -s -X POST "${OLLAMA_URL}/api/create" \
      -d "{\"name\":\"threatclaw-forensic\",\"from\":\"$FORENSIC_BASE\",\"system\":\"You are ThreatClaw forensic analysis engine. Perform deep investigation and return ONLY valid JSON. Never fabricate evidence or MITRE techniques not directly supported by the provided data.\",\"parameters\":{\"temperature\":0.2,\"num_ctx\":8192,\"num_predict\":2048}}" --max-time 30 > /dev/null 2>&1
    echo "[models] threatclaw-forensic ready"
  fi

  echo "[models] All AI models ready"
}

# Start model pull in background — core starts immediately
if [ "${TC_AUTO_PULL_MODELS:-true}" = "true" ]; then
  pull_models_background &
  echo "[init] AI model download started in background"
fi

# Trigger AUTO-START (IE + Telegram bot + sync scheduler) by hitting /api/tc/health
# See threatclaw_api.rs:153 — services auto-start on first authenticated health call.
(
  sleep 15
  AUTH_TOKEN_VAL="${GATEWAY_AUTH_TOKEN:-}"
  [ -z "$AUTH_TOKEN_VAL" ] && [ -f /run/secrets/tc_auth_token ] && AUTH_TOKEN_VAL=$(cat /run/secrets/tc_auth_token)
  for i in 1 2 3 4 5 6 7 8; do
    if curl -sf -H "Authorization: Bearer ${AUTH_TOKEN_VAL}" http://127.0.0.1:3000/api/tc/health > /dev/null 2>&1; then
      echo "[init] AUTO-START triggered via /api/tc/health (attempt $i)"
      break
    fi
    sleep 5
  done
) &

# ── CACAO graph fallback ──
# docker-compose mounts ./graphs:/app/graphs:ro from the host.
# If the host directory is empty (release install without git clone),
# the bind-mount hides the graphs bundled in the image.
# In that case we point TC_GRAPHS_DIR at the bundled copy.
_graphs_dir="${TC_GRAPHS_DIR:-/app/graphs/sigma}"
if [ -z "$(ls -A "$_graphs_dir" 2>/dev/null)" ]; then
  echo "[init] Graph dir '$_graphs_dir' is empty — using bundled graphs (/app/graphs-bundled/sigma)"
  export TC_GRAPHS_DIR=/app/graphs-bundled/sigma
else
  _count=$(ls -1 "$_graphs_dir"/*.yaml 2>/dev/null | wc -l)
  echo "[init] Graph dir ready — $_count YAML graphs found"
fi

# ── Start ThreatClaw core immediately ──
echo "[init] Starting ThreatClaw core..."
exec threatclaw run "$@"
