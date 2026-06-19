#!/usr/bin/env bash
# ThreatClaw endpoint agent — Linux uninstaller.
#
# Run as root (or via the gateway one-liner):
#   curl -fsSL get.threatclaw.io/agent/uninstall | sudo bash
#
# Removes everything install-agent.sh deployed: the systemd timer +
# service, /usr/local/bin/threatclaw-agent-sync (which embeds the
# webhook token in clear text), and the osquery package via the
# distro package manager. Anything missing is treated as "already
# gone" and reported as a skip, so the script is idempotent.
#
# Flags (env vars, since this is piped into bash):
#   TC_KEEP_OSQUERY=1   Leave osquery installed (some sites share
#                       osquery across multiple SOC products).
#
# shellcheck disable=SC2059
set -uo pipefail

c_cyan="\033[36m"; c_red="\033[31m"; c_yel="\033[33m"; c_grn="\033[32m"; c_dim="\033[2m"; c_off="\033[0m"
log()   { printf "${c_cyan}[ThreatClaw]${c_off} %s\n" "$*"; }
step()  { printf "  → %s\n" "$*"; }
skip()  { printf "  ${c_dim}· %s${c_off}\n" "$*"; }
done_() { printf "  ${c_grn}✓ %s${c_off}\n" "$*"; }
warn2() { printf "  ${c_yel}! %s${c_off}\n" "$*"; }
die()   { printf "${c_red}[ThreatClaw] %s${c_off}\n" "$*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
  die "Root privileges required. Re-run with sudo."
fi

log "Uninstalling ThreatClaw endpoint agent..."

# ── 1. systemd timer + service ─────────────────────────────────────
step "systemd units (threatclaw-agent.timer / .service)"
units_removed=0
for unit in threatclaw-agent.timer threatclaw-agent.service; do
  if systemctl list-unit-files --type=timer,service 2>/dev/null | grep -q "^${unit}"; then
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/${unit}"
    units_removed=$((units_removed + 1))
  fi
done
if [[ $units_removed -gt 0 ]]; then
  systemctl daemon-reload 2>/dev/null || true
  done_ "${units_removed} unit(s) removed"
else
  skip "not present"
fi

# Legacy cron path — early installs used this before systemd.
if crontab -l 2>/dev/null | grep -q 'threatclaw-agent-sync'; then
  step "crontab entry (legacy)"
  ( crontab -l 2>/dev/null | grep -v 'threatclaw-agent-sync' ) | crontab - || true
  done_ "removed"
fi

# ── 2. agent script (contains the webhook token in clear) ───────────
step "/usr/local/bin/threatclaw-agent-sync"
if [[ -f /usr/local/bin/threatclaw-agent-sync ]]; then
  rm -f /usr/local/bin/threatclaw-agent-sync
  done_ "removed"
else
  skip "not present"
fi

# ── 3. osquery package ─────────────────────────────────────────────
if [[ "${TC_KEEP_OSQUERY:-0}" == "1" ]]; then
  step "osquery — kept (TC_KEEP_OSQUERY=1)"
else
  step "osquery"
  if command -v osqueryi >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get -qq remove --purge -y osquery >/dev/null 2>&1 && done_ "apt purge ok" || warn2 "apt-get remove returned non-zero"
    elif command -v dnf >/dev/null 2>&1; then
      dnf -q remove -y osquery >/dev/null 2>&1 && done_ "dnf remove ok" || warn2 "dnf remove returned non-zero"
    elif command -v yum >/dev/null 2>&1; then
      yum -q remove -y osquery >/dev/null 2>&1 && done_ "yum remove ok" || warn2 "yum remove returned non-zero"
    else
      warn2 "no supported package manager — remove osquery manually"
    fi
  else
    skip "not present"
  fi
fi

# ── 4. residual state ──────────────────────────────────────────────
# Both /var/log/osquery and /var/osquery hold osquery's own logs &
# database, not TC data — leave them unless osquery was uninstalled.
if [[ "${TC_KEEP_OSQUERY:-0}" != "1" ]] && [[ -d /var/log/osquery ]]; then
  step "/var/log/osquery"
  rm -rf /var/log/osquery
  done_ "removed"
fi

# ── 5. Token reminder ──────────────────────────────────────────────
echo
log "Done."
echo
printf "${c_yel}    Important: the webhook token that was embedded in this host's${c_off}\n"
printf "${c_yel}    agent script is now off the disk but the gateway still accepts${c_off}\n"
printf "${c_yel}    it. Revoke it from the dashboard:${c_off}\n"
printf "${c_yel}        Skills -> Osquery -> Revoke / regenerate webhook token${c_off}\n"
echo
