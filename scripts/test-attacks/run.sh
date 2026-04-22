#!/usr/bin/env bash
# ThreatClaw — Attack scenario harness.
#
# Runs known attacks from the current machine against the TARS lab, then
# polls the ThreatClaw API on CASE to verify each attack produced its
# expected sigma_alert within the sync window.
#
# Environment overrides:
#   TARS_HOST     TARS public IP (default 62.210.201.235)
#   TC_URL        ThreatClaw dashboard base URL (default https://163.172.53.55:8445)
#   TIMEOUT_MIN   how long to wait for detection per scenario (default 5)
#
# Usage:
#   ./run.sh                   # all scenarios
#   ./run.sh mssql_brute       # one scenario by id
#   ./run.sh -l                # list scenarios + exit

set -euo pipefail

TARS_HOST="${TARS_HOST:-62.210.201.235}"
TC_URL="${TC_URL:-https://163.172.53.55:8445}"
TIMEOUT_MIN="${TIMEOUT_MIN:-5}"

# ── ANSI colours (match SOC console palette) ──
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; D='\033[0;2m'; N='\033[0m'

require_cmd() {
  local cmd="$1"; local hint="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf "${R}missing:${N} %s — install hint: %s\n" "$cmd" "$hint" >&2
    return 1
  fi
}

# ── Fetch latest N alerts from the TC API and count those matching the rule.
# The /api/tc/alerts endpoint filters on level/status only; rule_id is
# filtered here to keep the harness self-contained (no backend change
# required, same deploy cadence as the core).
count_for_rule() {
  local rule_id="$1"
  curl -skS "${TC_URL}/api/tc/alerts?limit=500" 2>/dev/null \
    | RULE_ID="$rule_id" python3 -c "
import sys, json, os
rid = os.environ['RULE_ID']
try:
    d = json.load(sys.stdin)
    print(sum(1 for a in d.get('alerts', []) if a.get('rule_id') == rid))
except Exception:
    print(0)
"
}

# ── Wait until count for rule grows, up to TIMEOUT_MIN ──
wait_for_fire() {
  local rule_id="$1"; local baseline="$2"
  local deadline=$(( $(date +%s) + TIMEOUT_MIN * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 30
    local cur; cur=$(count_for_rule "$rule_id")
    if [ "$cur" -gt "$baseline" ]; then
      echo "$cur"
      return 0
    fi
    printf "${D}  … still waiting (rule %s: %s → %s)${N}\n" "$rule_id" "$baseline" "$cur" >&2
  done
  return 1
}

# ── Scenarios ──────────────────────────────────────────────────────────

attack_mssql_brute() {
  # OpenCanary MSSQL logtype 9001 = login attempt. Port 1433 on TARS is
  # a honeypot — no real DB behind it. Hitting with raw TCP + fake login
  # packet triggers the rule.
  # We use python's socket to avoid requiring a MSSQL client on DEV.
  python3 - <<PY
import socket, struct
s = socket.create_connection(("$TARS_HOST", 1433), timeout=5)
# TDS pre-login — OpenCanary sees any connect on 1433 as an attempt
s.send(b"\\x12\\x01\\x00\\x2f\\x00\\x00\\x00\\x00\\x00\\x00\\x15\\x00\\x06")
s.close()
PY
}

attack_ssh_canary() {
  # OpenCanary SSH runs on 2223 — any banner fetch or login attempt fires.
  require_cmd ssh "apt install openssh-client" || return 1
  # Use sshpass-less deliberate fail: connect with bad key, non-interactive.
  timeout 6 ssh -p 2223 -o StrictHostKeyChecking=no -o BatchMode=yes \
    -o PasswordAuthentication=no -o ConnectTimeout=5 \
    -i /dev/null attacker@"$TARS_HOST" exit 2>/dev/null || true
}

attack_smb_canary() {
  # OpenCanary SMB honeypot on 445.
  require_cmd smbclient "apt install smbclient" || return 1
  timeout 6 smbclient -U 'sa%Summer2024' "//${TARS_HOST}/Partage" -c 'ls' 2>/dev/null || true
}

attack_ftp_canary() {
  # OpenCanary FTP on 21.
  require_cmd curl "apt install curl" || return 1
  curl -sS --connect-timeout 5 --max-time 6 \
    -u "admin:admin123" "ftp://${TARS_HOST}/" >/dev/null 2>&1 || true
}

attack_port_scan() {
  # OpenCanary portscan rule needs ≥5 ports in a short window.
  require_cmd nmap "apt install nmap" || return 1
  nmap -Pn -n --max-retries 0 -T4 -p 21,22,23,445,1433,3306,8888 \
    "$TARS_HOST" >/dev/null 2>&1 || true
}

attack_ssh_target_brute() {
  # openssh-server on 2222 is a REAL ssh with fake creds. Hydra
  # bruteforce triggers 5716 (ssh auth failure) on the Wazuh agent
  # watching TARS /var/log/auth.log.
  require_cmd hydra "apt install hydra" || return 1
  printf "admin\nroot\n" > /tmp/.tc-users
  printf "password\n123456\nadmin\n" > /tmp/.tc-pass
  timeout 15 hydra -L /tmp/.tc-users -P /tmp/.tc-pass -t 4 -s 2222 -f \
    ssh://"$TARS_HOST" 2>/dev/null || true
  rm -f /tmp/.tc-users /tmp/.tc-pass
}

# ── Scenario registry: id, human label, attack fn, expected rule id ──
SCENARIOS=(
  "mssql_brute | OpenCanary MSSQL probe on :1433     | attack_mssql_brute      | wazuh-100701"
  "ssh_canary  | OpenCanary SSH banner on :2223      | attack_ssh_canary       | wazuh-100702"
  "smb_canary  | OpenCanary SMB login on :445        | attack_smb_canary       | wazuh-100706"
  "ftp_canary  | OpenCanary FTP login on :21         | attack_ftp_canary       | wazuh-100705"
  "port_scan   | Portscan on multiple ports          | attack_port_scan        | wazuh-100707"
  "ssh_target_brute | Hydra SSH brute on :2222        | attack_ssh_target_brute | wazuh-5716"
)

# ── Runner ────────────────────────────────────────────────────────────

list_scenarios() {
  printf "%-18s %-40s %s\n" ID LABEL "EXPECTED RULE"
  for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r id label fn rule <<< "$entry"
    printf "%-18s %-40s %s\n" "$(echo $id)" "$(echo $label)" "$(echo $rule)"
  done
}

run_scenario() {
  local id="$1" label="$2" fn="$3" expected="$4"
  printf "${Y}▶${N} %-18s %s\n" "$id" "$label"

  local baseline; baseline=$(count_for_rule "$expected")
  printf "  baseline count for %s: %s\n" "$expected" "$baseline"

  printf "  launching attack...\n"
  if ! "$fn"; then
    printf "  ${R}SKIP${N} — attack prerequisites missing\n"
    return 2
  fi
  printf "  attack sent, waiting up to %s min for detection...\n" "$TIMEOUT_MIN"

  if final=$(wait_for_fire "$expected" "$baseline"); then
    printf "  ${G}PASS${N} %s → count %s → %s (+%s)\n" "$expected" "$baseline" "$final" "$((final - baseline))"
    return 0
  fi
  printf "  ${R}FAIL${N} %s never fired within %s min\n" "$expected" "$TIMEOUT_MIN"
  return 1
}

main() {
  if [ "${1:-}" = "-l" ] || [ "${1:-}" = "--list" ]; then
    list_scenarios; exit 0
  fi

  require_cmd curl "apt install curl" || exit 1
  require_cmd python3 "apt install python3" || exit 1

  local filter="${1:-}"
  local pass=0 fail=0 skip=0

  for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r id label fn rule <<< "$entry"
    id=$(echo $id); label=$(echo $label); fn=$(echo $fn); rule=$(echo $rule)
    if [ -n "$filter" ] && [ "$id" != "$filter" ]; then continue; fi
    if run_scenario "$id" "$label" "$fn" "$rule"; then
      pass=$((pass + 1))
    else
      rc=$?
      if [ $rc -eq 2 ]; then skip=$((skip + 1)); else fail=$((fail + 1)); fi
    fi
    echo
  done

  printf "${G}passed:${N} %d   ${R}failed:${N} %d   ${Y}skipped:${N} %d\n" "$pass" "$fail" "$skip"
  [ "$fail" -eq 0 ]
}

main "$@"
