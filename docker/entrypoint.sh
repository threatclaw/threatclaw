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
  set +e
  touch /shared/.env.token 2>/dev/null || chmod 777 /shared 2>/dev/null
  echo "TC_CORE_TOKEN=${GATEWAY_AUTH_TOKEN}" > /shared/.env.token 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "[init] Token written to /shared/.env.token for dashboard"
  else
    echo "[init] WARN: Could not write token to /shared — set TC_CORE_TOKEN manually"
  fi
  set -e
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
          -d "{\"name\":\"threatclaw-l1\",\"from\":\"${L1_MODEL}\",\"system\":\"$(head -20 /app/docker/Modelfile.threatclaw-l1 | grep -A999 'SYSTEM' | grep -v 'SYSTEM\|PARAMETER' | tr '\n' ' ' | sed 's/"/\\"/g')\"}" > /dev/null 2>&1 && \
          echo "[init] threatclaw-l1 created" || \
          echo "[init] WARNING: Failed to create threatclaw-l1"
      fi
    fi

    # Pull L2 Forensic model (Foundation-Sec Reasoning)
    L2_BASE="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF"
    if ! echo "$MODELS" | grep -q "threatclaw-l2"; then
      echo "[init] Pulling L2 forensic base model (this may take a while — ~8.5 GB)..."
      curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\":\"$L2_BASE\",\"stream\":false}" > /dev/null 2>&1 && \
        echo "[init] L2 base model pulled" || \
        echo "[init] WARNING: Failed to pull L2 base model"
      # Create threatclaw-l2
      echo "[init] Creating threatclaw-l2..."
      curl -s -X POST "${OLLAMA_URL}/api/create" \
        -d "{\"name\":\"threatclaw-l2\",\"from\":\"$L2_BASE\",\"system\":\"Tu es un analyste forensique expert de ThreatClaw. Tu montres ton raisonnement étape par étape. Réponds en JSON structuré.\",\"parameters\":{\"temperature\":0.2,\"num_ctx\":8192}}" --max-time 30 > /dev/null 2>&1 && \
        echo "[init] threatclaw-l2 created" || \
        echo "[init] WARNING: Failed to create threatclaw-l2"
    else
      echo "[init] L2 model already present: threatclaw-l2"
    fi

    # Pull L3 Instruct model (Foundation-Sec Instruct)
    L3_BASE="hf.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF"
    if ! echo "$MODELS" | grep -q "threatclaw-l3"; then
      echo "[init] Pulling L3 instruct base model (~4.9 GB)..."
      curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\":\"$L3_BASE\",\"stream\":false}" > /dev/null 2>&1 && \
        echo "[init] L3 base model pulled" || \
        echo "[init] WARNING: Failed to pull L3 base model"
      # Create threatclaw-l3
      echo "[init] Creating threatclaw-l3..."
      curl -s -X POST "${OLLAMA_URL}/api/create" \
        -d "{\"name\":\"threatclaw-l3\",\"from\":\"$L3_BASE\",\"system\":\"Tu es un expert SOC senior. Tu génères des playbooks SOAR, rapports d'incident, règles Sigma. En français, adapté PME NIS2/ANSSI.\",\"parameters\":{\"temperature\":0.3,\"num_ctx\":8192}}" --max-time 30 > /dev/null 2>&1 && \
        echo "[init] threatclaw-l3 created" || \
        echo "[init] WARNING: Failed to create threatclaw-l3"
    else
      echo "[init] L3 model already present: threatclaw-l3"
    fi

    echo "[init] Ollama models ready:"
    curl -s "${OLLAMA_URL}/api/tags" | python3 -c "
import sys,json
models = json.load(sys.stdin).get('models',[])
for m in models:
    size_gb = m.get('size',0) / 1e9
    print(f'  {m[\"name\"]:30s} {size_gb:.1f} GB')
print(f'  Total: {len(models)} models')
" 2>/dev/null || echo "  (could not list models)"
  fi
fi

echo "[init] Starting ThreatClaw core..."
exec threatclaw run "$@"
