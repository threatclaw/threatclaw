#!/usr/bin/env bash
# ThreatClaw — post-deploy smoke test for the staging environment.
#
# Runs on the staging host after deploy-remote.sh completes. Exercises
# six end-to-end contracts that matter for a beta release:
#
#   1. gateway /api/health returns 200
#   2. /api/tc/health returns a version string
#   3. grounding mode is 'strict' (or the operator-chosen value, but
#      never Off on a fresh install)
#   4. POST /api/tc/chat round-trips — L0 bot + DB persistence + return
#   5. the conversation from step 4 is readable via
#      GET /api/tc/conversations/{id}/messages
#   6. V49 starter Sigma pack is loaded (>=12 rules with id LIKE 'lnx-%')
#
# Exits 0 on all passes, 1 on the first failure. Emits one line per
# check for the workflow log.

set -euo pipefail

# Nginx fronts core on 8445 HTTPS with a self-signed cert — curl -k skips
# the verification, fine inside the trusted staging network.
BASE="${BASE:-https://127.0.0.1:8445}"
DB_CONTAINER="${DB_CONTAINER:-threatclaw-threatclaw-db-1}"

# Read the gateway token from the Docker secret file (preferred) or .env
TOKEN=""
if [ -r /opt/threatclaw/secrets/tc_auth_token.txt ]; then
    TOKEN=$(sudo cat /opt/threatclaw/secrets/tc_auth_token.txt)
elif [ -f /opt/threatclaw/.env ]; then
    TOKEN=$(sudo grep '^TC_AUTH_TOKEN=' /opt/threatclaw/.env | cut -d= -f2)
fi
if [ -z "$TOKEN" ]; then
    echo "[smoke] FAIL: no TC_AUTH_TOKEN available"; exit 1
fi

fail() { echo "[smoke FAIL] $*"; exit 1; }
pass() { echo "[smoke OK  ] $*"; }

H() {
    curl -sSk --max-time 30 -H "Authorization: Bearer $TOKEN" "$@"
}

# ── 1. gateway health ────────────────────────────────────────────────────
if ! H "$BASE/api/health" >/dev/null; then
    fail "gateway /api/health unreachable"
fi
pass "/api/health"

# ── 2. tc health ─────────────────────────────────────────────────────────
TC_HEALTH=$(H "$BASE/api/tc/health" || true)
if ! echo "$TC_HEALTH" | grep -qi 'version'; then
    fail "/api/tc/health missing version — got: $(echo "$TC_HEALTH" | head -c 200)"
fi
pass "/api/tc/health ($(echo "$TC_HEALTH" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("version","?"))' 2>/dev/null || echo '?'))"

# ── 3. grounding mode strict ─────────────────────────────────────────────
CFG=$(H "$BASE/api/tc/config")
MODE=$(echo "$CFG" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("llm_validation_mode",""))' 2>/dev/null || true)
if [ "$MODE" != "strict" ]; then
    fail "llm_validation_mode='$MODE' (expected 'strict' after V48)"
fi
pass "grounding=strict"

# ── 4. chat round-trip ───────────────────────────────────────────────────
CHAT_RESP=$(H "$BASE/api/tc/chat" -X POST -H 'Content-Type: application/json' \
    -d '{"message":"status","user_id":"smoke-test"}')
CONV=$(echo "$CHAT_RESP" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("conversation_id",""))' 2>/dev/null || true)
if [ -z "$CONV" ]; then
    fail "POST /api/tc/chat — no conversation_id in response: $(echo "$CHAT_RESP" | head -c 200)"
fi
pass "chat round-trip conv=$CONV"

# ── 5. conversation persisted ────────────────────────────────────────────
MSG_COUNT=$(H "$BASE/api/tc/conversations/$CONV/messages" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d.get("messages",[])))' 2>/dev/null || echo 0)
if [ "$MSG_COUNT" -lt 2 ]; then
    fail "conversation $CONV has $MSG_COUNT messages (expected >= 2)"
fi
pass "conversation persisted ($MSG_COUNT messages)"

# ── 6. V49 Sigma pack ────────────────────────────────────────────────────
SIG_COUNT=$(docker exec "$DB_CONTAINER" psql -U threatclaw -d threatclaw -tAc \
    "SELECT COUNT(*) FROM sigma_rules WHERE id LIKE 'lnx-%'" 2>/dev/null | tr -d '[:space:]' || echo 0)
if [ "${SIG_COUNT:-0}" -lt 12 ]; then
    fail "V49 Sigma pack has $SIG_COUNT rules (expected >= 12)"
fi
pass "V49 Sigma pack loaded ($SIG_COUNT rules)"

# ── Cleanup test conversation ────────────────────────────────────────────
H "$BASE/api/tc/conversations/$CONV" -X DELETE >/dev/null 2>&1 || true

echo "[smoke] all 6 checks passed"
