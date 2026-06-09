#!/usr/bin/env bash
# scripts/capture-sentinel-fixtures.sh
# Captures realistic Azure Sentinel REST responses into tests/fixtures/sentinel/
# for offline unit and integration tests. Requires /tmp/sentinel-test/env.sh
# and /tmp/sentinel-test/.secret to exist.
set -euo pipefail

. /tmp/sentinel-test/env.sh
SECRET="$(cat /tmp/sentinel-test/.secret)"
DEST="$(git rev-parse --show-toplevel)/tests/fixtures/sentinel"
mkdir -p "$DEST"

echo "Acquiring ARM token..."
TOKEN_ARM=$(curl -s -X POST "https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "scope=https://management.azure.com/.default" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_secret=${SECRET}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

TOKEN_LA=$(curl -s -X POST "https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "scope=https://api.loganalytics.io/.default" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_secret=${SECRET}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

BASE="https://management.azure.com/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.OperationalInsights/workspaces/${WS}/providers/Microsoft.SecurityInsights"

echo "Capturing incidents list..."
curl -s -H "Authorization: Bearer $TOKEN_ARM" "${BASE}/incidents?api-version=${API}" > "$DEST/incidents_list.json"

INC_ID=$(python3 -c "import json; print(json.load(open('$DEST/incidents_list.json'))['value'][0]['name'])")
echo "Using incident $INC_ID"

curl -s -X POST -H "Authorization: Bearer $TOKEN_ARM" -H "Content-Length: 0" \
  "${BASE}/incidents/${INC_ID}/alerts?api-version=${API}" > "$DEST/alerts_for_incident.json"

curl -s -X POST -H "Authorization: Bearer $TOKEN_ARM" -H "Content-Length: 0" \
  "${BASE}/incidents/${INC_ID}/entities?api-version=${API}" > "$DEST/entities_for_incident.json"

curl -s -H "Authorization: Bearer $TOKEN_ARM" "${BASE}/alertRules?api-version=${API}" > "$DEST/analytic_rules_list.json"

# Capture a Scheduled rule detail (200) — pick the first rule from the list
echo "Capturing a Scheduled rule detail (200)..."
SCHED_RULE=$(python3 -c "
import json
rules = json.load(open('$DEST/analytic_rules_list.json'))['value']
for r in rules:
    if r.get('kind') == 'Scheduled':
        print(r['name']); break
")
if [ -z "$SCHED_RULE" ]; then
  echo "ERROR: no Scheduled rule found in the workspace; analytic_rule_scheduled_detail.json cannot be captured" >&2
  exit 1
fi
curl -s -H "Authorization: Bearer $TOKEN_ARM" "${BASE}/alertRules/${SCHED_RULE}?api-version=${API}" > "$DEST/analytic_rule_scheduled_detail.json"

# Capture a deliberate 404 for fallback path coverage
echo "Capturing a deliberate 404 (random non-existent rule UUID)..."
FAKE_RULE=$(python3 -c "import uuid; print(uuid.uuid4())")
curl -s -H "Authorization: Bearer $TOKEN_ARM" "${BASE}/alertRules/${FAKE_RULE}?api-version=${API}" > "$DEST/analytic_rule_not_found_404.json"

echo "Capturing KQL probe..."
curl -s -X POST -H "Authorization: Bearer $TOKEN_LA" -H "Content-Type: application/json" \
  -d '{"query":"SecurityEvent | take 1 | project TimeGenerated, EventID, Computer, Account"}' \
  "https://api.loganalytics.io/v1/workspaces/${WS_ID}/query" > "$DEST/kql_securityevent_1row.json"

# 403 fixture for the comment write path (current app has only Reader role)
CID=$(python3 -c "import uuid; print(uuid.uuid4())")
curl -s -X PUT -H "Authorization: Bearer $TOKEN_ARM" -H "Content-Type: application/json" \
  -d '{"properties":{"message":"fixture-capture"}}' \
  "${BASE}/incidents/${INC_ID}/comments/${CID}?api-version=${API}" > "$DEST/comment_403.json"

# Token response (with access_token redacted for commit safety)
python3 -c "
import json
sample = {
  'token_type': 'Bearer',
  'expires_in': 3599,
  'ext_expires_in': 3599,
  'access_token': 'REDACTED_BY_CAPTURE_SCRIPT'
}
json.dump(sample, open('$DEST/token_response.json', 'w'), indent=2)
"

# Redact tenant, subscription, workspace, client and SP identifiers from
# captured fixtures so they are commit-safe (Microsoft response shapes are not
# secret, but customer tenant + app registration IDs are considered confidential)
echo "Redacting tenant + subscription + client + SP + RG + WS identifiers..."
SP_OBJECT_ID="5dc8323e-302d-4139-8fda-b0e691692e5c"
for f in "$DEST"/*.json; do
  sed -i \
    -e "s/${TENANT}/00000000-0000-0000-0000-000000000000/g" \
    -e "s/${SUB}/11111111-1111-1111-1111-111111111111/g" \
    -e "s/${WS_ID}/22222222-2222-2222-2222-222222222222/g" \
    -e "s/${CLIENT_ID}/33333333-3333-3333-3333-333333333333/g" \
    -e "s/${SP_OBJECT_ID}/44444444-4444-4444-4444-444444444444/g" \
    -e "s/${RG}/lab-rg/g" \
    -e "s/${WS}/lab-workspace/g" \
    -e "s/SHIR-Hive/LAB-VM-01/g" \
    "$f"
done

echo "Done. Captured $(ls "$DEST" | wc -l) fixtures."
ls -la "$DEST"
