#!/usr/bin/env bash
# ThreatClaw — Docker entrypoint
# Handles first-time setup, migrations, auth token, and background model pull.
set -euo pipefail

echo "╔══════════════════════════════════════════════════╗"
echo "║          ThreatClaw — Starting...                ║"
echo "╚══════════════════════════════════════════════════╝"

# ── Wait for PostgreSQL ──
echo "[init] Waiting for PostgreSQL..."
for i in $(seq 1 60); do
  if pg_isready -h "${TC_DB_HOST:-threatclaw-db}" -p "${TC_DB_PORT:-5432}" -U "${POSTGRES_USER:-threatclaw}" -q 2>/dev/null; then
    echo "[init] PostgreSQL ready"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "[init] ERROR: PostgreSQL not reachable after 60s"
    exit 1
  fi
  sleep 1
done

# ── Generate auth token if not provided ──
if [ -z "${GATEWAY_AUTH_TOKEN:-}" ]; then
  EXISTING_TOKEN=$(PGPASSWORD="${POSTGRES_PASSWORD:-threatclaw}" psql -h "${TC_DB_HOST:-threatclaw-db}" -U "${POSTGRES_USER:-threatclaw}" -d "${POSTGRES_DB:-threatclaw}" -tAc \
    "SELECT trim(both '\"' from value::text) FROM settings WHERE key = 'channels.gateway_auth_token' LIMIT 1" 2>/dev/null || echo "")

  if [ -n "$EXISTING_TOKEN" ] && [ "$EXISTING_TOKEN" != "" ]; then
    export GATEWAY_AUTH_TOKEN="$EXISTING_TOKEN"
    echo "[init] Auth token loaded from DB"
  else
    export GATEWAY_AUTH_TOKEN=$(openssl rand -hex 32)
    echo "[init] Auth token generated (new installation)"
  fi
fi

# ── Write token to shared volume for dashboard ──
set +e
if [ -d "/shared" ]; then
  chmod 777 /shared 2>/dev/null
  echo "TC_CORE_TOKEN=${GATEWAY_AUTH_TOKEN}" > /shared/.env.token 2>/dev/null
  [ $? -eq 0 ] && echo "[init] Token shared with dashboard" || echo "[init] WARN: Token not shared — dashboard uses TC_AUTH_TOKEN from .env"
fi
set -e

# ── Ensure Fluent Bit staging trigger exists ──
echo "[init] Setting up log ingestion trigger..."
PGPASSWORD="${POSTGRES_PASSWORD:-threatclaw}" psql -h "${TC_DB_HOST:-threatclaw-db}" -U "${POSTGRES_USER:-threatclaw}" -d "${POSTGRES_DB:-threatclaw}" -q <<'TRIGGERSQL' 2>/dev/null || echo "[init] WARN: Could not create log trigger"
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

  # Pull L1
  L1_MODEL="${TC_L1_MODEL:-qwen3:8b}"
  if ! echo "$MODELS" | grep -q "$L1_MODEL"; then
    echo "[models] Downloading L1 ($L1_MODEL) — ~5 GB..."
    curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\":\"$L1_MODEL\",\"stream\":false}" > /dev/null 2>&1
    echo "[models] L1 ready"
  fi

  # Create threatclaw-l1
  if ! echo "$MODELS" | grep -q "threatclaw-l1"; then
    echo "[models] Creating threatclaw-l1..."
    curl -s -X POST "${OLLAMA_URL}/api/create" \
      -d "{\"name\":\"threatclaw-l1\",\"from\":\"${L1_MODEL}\",\"system\":\"Tu es le moteur d'analyse de ThreatClaw. Réponds UNIQUEMENT en JSON structuré.\"}" > /dev/null 2>&1
    echo "[models] threatclaw-l1 created"
  fi

  # Pull L2
  L2_BASE="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF"
  if ! echo "$MODELS" | grep -q "threatclaw-l2"; then
    echo "[models] Downloading L2 Forensic — ~8.5 GB..."
    curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\":\"$L2_BASE\",\"stream\":false}" > /dev/null 2>&1
    curl -s -X POST "${OLLAMA_URL}/api/create" \
      -d "{\"name\":\"threatclaw-l2\",\"from\":\"$L2_BASE\",\"system\":\"Tu es un analyste forensique expert. Raisonne étape par étape. Réponds en JSON.\",\"parameters\":{\"temperature\":0.2,\"num_ctx\":8192}}" --max-time 30 > /dev/null 2>&1
    echo "[models] L2 ready"
  fi

  # Pull L3
  L3_BASE="hf.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF"
  if ! echo "$MODELS" | grep -q "threatclaw-l3"; then
    echo "[models] Downloading L3 Instruct — ~5 GB..."
    curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\":\"$L3_BASE\",\"stream\":false}" > /dev/null 2>&1
    curl -s -X POST "${OLLAMA_URL}/api/create" \
      -d "{\"name\":\"threatclaw-l3\",\"from\":\"$L3_BASE\",\"system\":\"Tu es un expert SOC. Génère des playbooks SOAR, rapports, règles Sigma. En français.\",\"parameters\":{\"temperature\":0.3,\"num_ctx\":8192}}" --max-time 30 > /dev/null 2>&1
    echo "[models] L3 ready"
  fi

  echo "[models] All AI models ready"
}

# Start model pull in background — core starts immediately
if [ "${TC_AUTO_PULL_MODELS:-true}" = "true" ]; then
  pull_models_background &
  echo "[init] AI model download started in background"
fi

# ── Start ThreatClaw core immediately ──
echo "[init] Starting ThreatClaw core..."
exec threatclaw run "$@"
