#!/usr/bin/env bash
# ThreatClaw — light wipe of operational data on staging CASE.
#
# Truncates the volatile / observational tables so the dashboard restarts
# with a clean view of what's flowing in right now. Preserves everything
# the operator explicitly configured: assets declared, sigma rules
# (including the V49 starter pack), suppression rules, channel secrets,
# LLM config, etc.
#
# Usage (from CASE, as tc-deploy or claude):
#   bash scripts/ci/wipe-staging-data.sh            # dry-run, shows counts
#   WIPE=yes bash scripts/ci/wipe-staging-data.sh   # actually truncates
#
# Safe to run multiple times. Does not touch the compose stack, certs,
# /opt/threatclaw/ files, or Wazuh.

set -euo pipefail

DB_CONTAINER="${DB_CONTAINER:-threatclaw-threatclaw-db-1}"
DB_USER="${DB_USER:-threatclaw}"
DB_NAME="${DB_NAME:-threatclaw}"

# Tables wiped — operational firehose + derived signal
WIPE_TABLES=(
    sigma_alerts
    findings
    cloud_findings
    incidents
    suppression_audit
    cve_exposure_alerts
    conversation_messages
    conversations
    graph_nodes
    graph_edges
    ml_scores
    certfr_alerts
    logs
    logs_fluentbit
    llm_calls
    job_events
    job_actions
    agent_jobs
)

# Tables kept on purpose:
#   settings, skill_configs, sigma_rules, suppression_rules, assets,
#   internal_networks, retention_config, secrets, routines, tool_capabilities,
#   refinery_schema_history, monthly_rssi_summary (matview — refreshes from
#   incidents so will recompute empty after wipe)

# Pick the docker invocation: plain for users in the docker group
# (tc-deploy), sudo fallback for admins who must elevate (claude).
DOCKER=docker
if ! docker ps >/dev/null 2>&1; then
    DOCKER="sudo docker"
fi

PSQL() {
    $DOCKER exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" "$@"
}

echo "[wipe] inventory BEFORE"
for t in "${WIPE_TABLES[@]}"; do
    count=$(PSQL -tAc "SELECT count(*) FROM $t" 2>/dev/null || echo '?')
    printf "  %-22s %s\n" "$t" "$count"
done

if [ "${WIPE:-no}" != "yes" ]; then
    echo
    echo "[wipe] DRY RUN — re-run with WIPE=yes to actually truncate"
    exit 0
fi

echo
echo "[wipe] truncating..."
# Single transaction, RESTART IDENTITY resets the sequences, CASCADE
# handles FK chains (sigma_alerts ← cve_exposure_alerts, conversations
# ← conversation_messages, etc.).
IFS=','; TABLES_CSV="${WIPE_TABLES[*]}"; IFS=$' \t\n'
PSQL -v ON_ERROR_STOP=1 -c "TRUNCATE TABLE ${TABLES_CSV} RESTART IDENTITY CASCADE;"

echo "[wipe] refreshing monthly_rssi_summary (will be empty)"
PSQL -c "REFRESH MATERIALIZED VIEW CONCURRENTLY monthly_rssi_summary;" 2>/dev/null || \
    PSQL -c "REFRESH MATERIALIZED VIEW monthly_rssi_summary;" 2>/dev/null || true

echo
echo "[wipe] inventory AFTER"
for t in "${WIPE_TABLES[@]}"; do
    count=$(PSQL -tAc "SELECT count(*) FROM $t" 2>/dev/null || echo '?')
    printf "  %-22s %s\n" "$t" "$count"
done

echo
echo "[wipe] done — next IE cycle (5 min) will produce fresh data"
