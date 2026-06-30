#!/usr/bin/env bash
# E2E validation on cyb06 of the detection clock-robustness fixes:
#   #11 — background services start at boot (not first /api/tc/health)
#   #10 — Sigma scan cursor keys on created_at (clock-drift immune)
#
# Read-only against the live test box. No mutation.
set -uo pipefail
H=root@149.71.41.85
DB='docker exec threatclaw-threatclaw-db-1 psql -U threatclaw -d threatclaw -tAF| -c'

echo "=================================================================="
echo " #11 — boot-start: services launched at boot, before any tc/health"
echo "=================================================================="
ssh -o StrictHostKeyChecking=no $H \
  "docker logs threatclaw-threatclaw-core-1 2>&1 | grep -E 'AUTO-START|Web gateway|started' | head -25"

echo
echo "=================================================================="
echo " #10a — persisted cursor format (expect {\"created_at\":..,\"id\":..})"
echo "=================================================================="
ssh $H "$DB \"SELECT value FROM settings WHERE user_id='_system' AND key='sigma_log_cursor'\""

echo
echo "=================================================================="
echo " #10b — clock drift present? future-dated rows vs cursor health"
echo "=================================================================="
ssh $H "$DB \"SELECT
  count(*) FILTER (WHERE time > now() + interval '60 seconds') AS future_time_rows,
  count(*) AS total_rows,
  max(created_at)::text AS last_insert,
  max(time)::text AS max_event_time
FROM logs\""

echo
echo "=================================================================="
echo " #10c — cursor advances over ~45s (proves the cycle consumes logs)"
echo "=================================================================="
C1=$(ssh $H "$DB \"SELECT value->>'created_at' || '#' || (value->>'id') FROM settings WHERE user_id='_system' AND key='sigma_log_cursor'\"")
echo "cursor t0: $C1"
sleep 45
C2=$(ssh $H "$DB \"SELECT value->>'created_at' || '#' || (value->>'id') FROM settings WHERE user_id='_system' AND key='sigma_log_cursor'\"")
echo "cursor t1: $C2"
if [ "$C1" != "$C2" ]; then echo "RESULT: cursor ADVANCED ✓"; else echo "RESULT: cursor unchanged (no new logs in window, or cycle>45s — check alerts below)"; fi

echo
echo "=================================================================="
echo " #10d — detection alive: recent sigma_alerts (last 15 min)"
echo "=================================================================="
ssh $H "$DB \"SELECT
  count(*) FILTER (WHERE matched_at > now() - interval '15 minutes') AS alerts_15m,
  count(*) AS alerts_total,
  max(matched_at)::text AS last_alert
FROM sigma_alerts\""

echo
echo "=================================================================="
echo " incidents formed (IE ticker alive, last 15 min)"
echo "=================================================================="
ssh $H "$DB \"SELECT count(*) FILTER (WHERE created_at > now() - interval '15 minutes') AS incidents_15m,
  count(*) AS incidents_total, max(created_at)::text AS last_incident FROM incidents\""
