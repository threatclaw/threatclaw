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

attack_mysql_canary() {
  # OpenCanary MySQL on 3306. Logs logtype 8001 ONLY on a proper
  # client-side auth attempt, not on a raw TCP connect — a garbage
  # packet is silently dropped. The emulator reads the greeting, waits
  # for the client to send CAP+user+password, and only then logs.
  python3 - <<PY
import socket
s = socket.create_connection(("$TARS_HOST", 3306), timeout=6)
try:
    s.recv(128)  # server greeting (~82 bytes)
    # Minimal MySQL 4.1+ client auth packet: capabilities, max_pkt,
    # charset, user="root", 20-byte auth response, plugin name.
    body = (
        b"\\x85\\xa6\\xff\\x01\\x00\\x00\\x00\\x01\\x21" + b"\\x00" * 23
        + b"root\\x00" + b"\\x14" + b"A" * 20
        + b"mysql_native_password\\x00"
    )
    hdr = len(body).to_bytes(3, "little") + b"\\x01"
    s.sendall(hdr + body)
    s.recv(128)  # Access denied response — OpenCanary has logged by now
except Exception:
    pass
finally:
    s.close()
PY
}

attack_ftp_canary() {
  # OpenCanary FTP on 21.
  require_cmd curl "apt install curl" || return 1
  curl -sS --connect-timeout 5 --max-time 6 \
    -u "admin:admin123" "ftp://${TARS_HOST}/" >/dev/null 2>&1 || true
}

attack_port_scan() {
  # OpenCanary portscan rule (logtype 13001) on hp-printer-3f triggers on
  # SNMP queries to :161 with a known community string. Analysis of the 8
  # real-world fires showed they all came from SNMP scanners walking the
  # standard system OIDs, not from classic TCP SYN scans. Reproduce that.
  python3 - <<PY
import socket
# Build a minimal SNMP v1 GET packet for OID .1.3.6.1.2.1.1.1.0 (sysDescr),
# community "public". Stdlib-only so the harness does not need snmpwalk.
pkt = bytes.fromhex(
    "302602010004067075626c6963a01902040d5c1d0e"
    "0201000201003010301006082b060102010101000500"
)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(pkt, ("$TARS_HOST", 161))
    try: s.recv(512)
    except: pass
finally:
    s.close()
PY
}

attack_telnet_canary() {
  # OpenCanary Telnet on 23 (hp-printer-3f). Logs logtype 6001 on any
  # login-prompt interaction, matched by Wazuh rule 100704. Replaces the
  # previous ssh_target_brute scenario which required the linuxserver
  # openssh-server container to propagate auth.log to the host Wazuh
  # agent — linuxserver images log only to stdout (docker json), which
  # the Wazuh agent does not tail.
  python3 - <<PY
import socket
s = socket.create_connection(("$TARS_HOST", 23), timeout=5)
try:
    s.recv(64)  # consume telnet banner
    s.sendall(b"admin\r\nadmin123\r\n")
    s.recv(256)
except Exception:
    pass
finally:
    s.close()
PY
}

# ── Scenario registry: id, human label, attack fn, expected rule id ──
#
# Five TCP-only scenarios in the default suite — every major OpenCanary
# protocol we have a working emulator for, running over TCP so any CI
# environment with outbound internet can drive them.
#
# Removed from default:
#   smb_canary — thinkst/opencanary SMB module tails a real Samba auth
#                log, not a listening TCP service; TARS does not run Samba.
#   port_scan  — requires outbound UDP :161 to reach TARS. Many CI
#                runners (including ours) strip UDP outbound, so the
#                scenario flakes. Runnable manually from a host with UDP
#                reachability via `./run.sh port_scan`.
SCENARIOS=(
  "mssql_brute   | OpenCanary MSSQL probe on :1433 | attack_mssql_brute   | wazuh-100701"
  "ssh_canary    | OpenCanary SSH banner on :2223  | attack_ssh_canary    | wazuh-100702"
  "mysql_canary  | OpenCanary MySQL probe on :3306 | attack_mysql_canary  | wazuh-100703"
  "ftp_canary    | OpenCanary FTP login on :21     | attack_ftp_canary    | wazuh-100705"
  "telnet_canary | OpenCanary Telnet login on :23  | attack_telnet_canary | wazuh-100704"
)

# Extra scenarios — runnable by id but not part of the default suite.
EXTRA_SCENARIOS=(
  "port_scan     | SNMP portscan on :161 UDP       | attack_port_scan     | wazuh-100707"
)

# ── Runner ────────────────────────────────────────────────────────────

list_scenarios() {
  printf "%-18s %-40s %s\n" ID LABEL "EXPECTED RULE"
  for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r id label fn rule <<< "$entry"
    printf "%-18s %-40s %s\n" "$(echo $id)" "$(echo $label)" "$(echo $rule)"
  done
  echo
  echo "Extra (not in default run, usable by id):"
  for entry in "${EXTRA_SCENARIOS[@]}"; do
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

  # When a specific id is requested, look in both default and extra lists
  # so `./run.sh port_scan` still works on a host with UDP reachability.
  local all_scenarios=("${SCENARIOS[@]}")
  if [ -n "$filter" ]; then
    all_scenarios+=("${EXTRA_SCENARIOS[@]}")
  fi

  for entry in "${all_scenarios[@]}"; do
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
