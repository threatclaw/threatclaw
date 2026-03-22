#!/usr/bin/env bash
# ThreatClaw — Docker entrypoint
# Handles first-time setup, migrations, auth token generation, and Ollama model pull.
set -euo pipefail

echo "╔══════════════════════════════════════════════════╗"
echo "║          ThreatClaw — Starting...                ║"
echo "╚══════════════════════════════════════════════════╝"

# ── Wait for PostgreSQL ──
echo "[init] Waiting for PostgreSQL..."
for i in $(seq 1 30); do
  if pg_isready -h "${TC_DB_HOST:-threatclaw-db}" -p "${TC_DB_PORT:-5432}" -U "${POSTGRES_USER:-threatclaw}" -q 2>/dev/null; then
    echo "[init] PostgreSQL ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "[init] ERROR: PostgreSQL not reachable after 30s"
    exit 1
  fi
  sleep 1
done

# ── Generate auth token if not provided ──
if [ -z "${GATEWAY_AUTH_TOKEN:-}" ]; then
  # Check if token exists in DB from previous run
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
if [ -d "/shared" ]; then
  echo "TC_CORE_TOKEN=${GATEWAY_AUTH_TOKEN}" > /shared/.env.token
  echo "[init] Token written to /shared/.env.token for dashboard"
fi

# ── Pull Ollama models if configured ──
OLLAMA_URL="${OLLAMA_BASE_URL:-http://ollama:11434}"
if [ "${TC_AUTO_PULL_MODELS:-true}" = "true" ]; then
  echo "[init] Checking Ollama models..."

  # Wait for Ollama
  for i in $(seq 1 60); do
    if curl -s "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
      break
    fi
    if [ "$i" -eq 60 ]; then
      echo "[init] WARNING: Ollama not reachable — skipping model pull"
      break
    fi
    sleep 2
  done

  if curl -s "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
    MODELS=$(curl -s "${OLLAMA_URL}/api/tags" | python3 -c "import sys,json; print(' '.join(m['name'] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null || echo "")

    # Pull L1 model if not present
    L1_MODEL="${TC_L1_MODEL:-qwen3:8b}"
    if ! echo "$MODELS" | grep -q "$L1_MODEL"; then
      echo "[init] Pulling L1 model: $L1_MODEL (this may take a while)..."
      curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\":\"$L1_MODEL\",\"stream\":false}" > /dev/null 2>&1 && \
        echo "[init] L1 model ready: $L1_MODEL" || \
        echo "[init] WARNING: Failed to pull L1 model"
    else
      echo "[init] L1 model already present: $L1_MODEL"
    fi

    # Create custom L1 modelfile if not present
    if ! echo "$MODELS" | grep -q "threatclaw-l1"; then
      if [ -f "/app/docker/Modelfile.threatclaw-l1" ]; then
        echo "[init] Creating threatclaw-l1 from Modelfile..."
        curl -s -X POST "${OLLAMA_URL}/api/create" \
          -d "{\"name\":\"threatclaw-l1\",\"modelfile\":\"$(cat /app/docker/Modelfile.threatclaw-l1 | sed 's/"/\\"/g' | tr '\n' '\\' | sed 's/\\/\\n/g')\"}" > /dev/null 2>&1 && \
          echo "[init] threatclaw-l1 created" || \
          echo "[init] WARNING: Failed to create threatclaw-l1"
      fi
    fi

    echo "[init] Ollama models: $(curl -s "${OLLAMA_URL}/api/tags" | python3 -c "import sys,json; print(', '.join(m['name'] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null || echo "unknown")"
  fi
fi

echo "[init] Starting ThreatClaw core..."
exec /app/threatclaw run "$@"
