#!/bin/bash
# ThreatClaw — End-to-End Test Script
# Tests the full Docker stack from a fresh start.

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }

echo "═══════════════════════════════════════════"
echo " ThreatClaw — End-to-End Test"
echo "═══════════════════════════════════════════"

# 1. Check images exist
info "Checking Docker images..."
docker images | grep -q "threatclaw/db" || fail "Image threatclaw/db:latest not found"
docker images | grep -q "threatclaw/dashboard" || fail "Image threatclaw/dashboard:latest not found"
docker images | grep -q "threatclaw/ml-engine" || fail "Image threatclaw/ml-engine:latest not found"
pass "All images present"

# 2. Check docker compose
info "Validating docker-compose.yml..."
cd "$(dirname "$0")"
docker compose config --quiet 2>/dev/null || fail "docker-compose.yml invalid"
pass "Compose file valid"

# 3. Test DB connection
info "Testing PostgreSQL connection..."
PGPASSWORD=${TC_DB_PASSWORD:-threatclaw} psql -h 127.0.0.1 -U threatclaw -d threatclaw -c "SELECT 1" > /dev/null 2>&1 || fail "PostgreSQL not accessible"
pass "PostgreSQL connected"

# 4. Test extensions
info "Checking PostgreSQL extensions..."
PGPASSWORD=${TC_DB_PASSWORD:-threatclaw} psql -h 127.0.0.1 -U threatclaw -d threatclaw -tAc "SELECT extname FROM pg_extension WHERE extname IN ('age','timescaledb','vector') ORDER BY extname" 2>/dev/null | while read ext; do
  pass "Extension: $ext"
done

# 5. Test API health
info "Testing Backend API..."
HEALTH=$(curl -sf http://127.0.0.1:3001/api/tc/health 2>/dev/null || echo '{}')
echo "$HEALTH" | grep -q '"status":"ok"' || fail "Backend API not healthy"
pass "Backend API OK"

# 6. Test Dashboard
info "Testing Dashboard..."
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" http://127.0.0.1:3001 2>/dev/null || echo "000")
[ "$HTTP_CODE" = "200" ] || fail "Dashboard not responding (HTTP $HTTP_CODE)"
pass "Dashboard HTTP 200"

# 7. Test Assets API
info "Testing Assets API..."
ASSETS=$(curl -sf http://127.0.0.1:3001/api/tc/assets/counts 2>/dev/null || echo '{}')
echo "$ASSETS" | grep -q "total" || fail "Assets API not working"
pass "Assets API OK"

# 8. Test Intelligence
info "Testing Intelligence API..."
SITUATION=$(curl -sf http://127.0.0.1:3001/api/tc/intelligence/situation 2>/dev/null || echo '{}')
echo "$SITUATION" | grep -q "global_score" || fail "Intelligence API not working"
pass "Intelligence API OK"

# 9. Test Scenarios
info "Testing Test Scenarios..."
SCENARIOS=$(curl -sf http://127.0.0.1:3001/api/tc/test/scenarios 2>/dev/null || echo '{}')
COUNT=$(echo "$SCENARIOS" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('scenarios',[])))" 2>/dev/null || echo "0")
[ "$COUNT" -ge 6 ] || fail "Test scenarios not loaded (got $COUNT)"
pass "$COUNT test scenarios available"

# 10. Test ML scores table
info "Testing ML scores table..."
PGPASSWORD=${TC_DB_PASSWORD:-threatclaw} psql -h 127.0.0.1 -U threatclaw -d threatclaw -c "SELECT count(*) FROM ml_scores" > /dev/null 2>&1 || fail "ml_scores table missing"
pass "ML scores table exists"

echo ""
echo "═══════════════════════════════════════════"
echo -e " ${GREEN}ALL TESTS PASSED${NC}"
echo "═══════════════════════════════════════════"
echo ""
echo "Dashboard: http://localhost:3001"
echo "API:       http://localhost:3001/api/tc/health"
