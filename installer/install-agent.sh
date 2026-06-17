#!/usr/bin/env bash
# ThreatClaw Agent Installer
#
# Preferred (keeps the token out of `ps`/shell history): pass it via env or file.
#   TC_URL=https://TC_IP:8445 TC_TOKEN=YOUR_TOKEN sudo -E bash -c "$(curl -fsSL get.threatclaw.io/agent)"
#   ... | sudo bash -s -- --url https://TC_IP:8445 --token-file /run/tc-token
# Still supported (token visible in argv during install):
#   curl -fsSL get.threatclaw.io/agent | sudo bash -s -- --url https://TC_IP:8445 --token YOUR_TOKEN
#
# Installs osquery, configures it as ThreatClaw Agent, starts the service.
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora, macOS (brew).

set -euo pipefail

# ── Defaults ──
TC_URL="${TC_URL:-}"
TC_TOKEN="${TC_TOKEN:-}"
AGENT_ID=""
# We don't pin osquery's version: pkg.osquery.io only keeps the latest in its
# apt/yum repos, so a `=5.12.1-*` pin breaks the install entirely the day
# upstream rotates. The agent works against any 5.x. Kept here for the
# log line only.
OSQUERY_VERSION_FLOOR="5.12.1"
SYNC_INTERVAL=300  # 5 minutes

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[ThreatClaw Agent]${NC} $*"; }
warn() { echo -e "${RED}[ThreatClaw Agent]${NC} $*" >&2; }
info() { echo -e "${BLUE}[ThreatClaw Agent]${NC} $*"; }

# ── Parse args ──
while [[ $# -gt 0 ]]; do
  case $1 in
    --url)        TC_URL="$2"; shift 2 ;;
    --token)      TC_TOKEN="$2"; shift 2 ;;
    --token-file) TC_TOKEN="$(cat "$2")"; shift 2 ;;
    --id)         AGENT_ID="$2"; shift 2 ;;
    --help)
      echo "Usage: install-agent.sh --url https://TC:8445 --token TOKEN [--id AGENT_ID]"
      exit 0 ;;
    *) shift ;;
  esac
done

if [ -z "$TC_URL" ]; then
  warn "Missing --url (ThreatClaw instance URL)"
  echo "Usage: curl -fsSL get.threatclaw.io/agent | sudo bash -s -- --url https://TC_IP:8445 --token TOKEN"
  exit 1
fi

if [ -z "$TC_TOKEN" ]; then
  warn "Missing --token (webhook token from ThreatClaw dashboard)"
  exit 1
fi

# Generate agent ID from hostname if not provided
if [ -z "$AGENT_ID" ]; then
  AGENT_ID="agent-$(hostname -s | tr '[:upper:]' '[:lower:]')-$(cat /etc/machine-id 2>/dev/null | head -c 8 || echo $$)"
fi

# ── Check root ──
if [ "$(id -u)" -ne 0 ]; then
  warn "This script must be run as root (sudo)"
  exit 1
fi

# ── Pre-flight ──
# Verify the server is reachable AND the token is valid BEFORE touching the
# system, so a wrong URL/port (often :8445, not 443) or a bad token fails fast
# instead of leaving a half-configured agent that silently never reports.
# -k matches the sync script (self-signed cert); this checks reachability +
# token, not cert validity.
info "Pre-flight: checking connection and token at $TC_URL ..."
ping_code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST -H "X-Webhook-Token: $TC_TOKEN" \
  "${TC_URL}/api/tc/webhook/ping/osquery" 2>/dev/null || echo "000")
case "$ping_code" in
  # Only abort on the two unambiguous failures: a clearly-rejected token (401) or
  # no response at all (000 = server/port/firewall). ANY other HTTP response means
  # the server is reachable and the token check is merely inconclusive (older
  # server with no ping endpoint, a proxy filtering this path, a transient 5xx,
  # rate-limit...) — don't block a valid install; the first sync is the real test.
  2??) log "Pre-flight OK — server reachable and token valid" ;;
  401) warn "Server reachable but the webhook token is INVALID — check the token (Dashboard > Skills > Osquery). Nothing was installed."; exit 1 ;;
  000) warn "Cannot reach ThreatClaw at $TC_URL — check the URL and PORT (often :8445, not 443) and any firewall between this host and the server. Nothing was installed."; exit 1 ;;
  *)   warn "Server reachable; token check inconclusive (HTTP $ping_code) — proceeding (the first sync is the real test)." ;;
esac

# ── Detect OS ──
detect_os() {
  if [ -f /etc/debian_version ]; then
    echo "debian"
  elif [ -f /etc/redhat-release ]; then
    echo "redhat"
  elif [ "$(uname)" = "Darwin" ]; then
    echo "macos"
  else
    echo "unknown"
  fi
}

OS=$(detect_os)
log "Detected OS: $OS ($(uname -m))"

# ── Install osquery ──
install_osquery() {
  if command -v osqueryd >/dev/null 2>&1; then
    log "osquery already installed ($(osqueryd --version 2>/dev/null | head -1))"
    return 0
  fi

  log "Installing osquery (latest from pkg.osquery.io, $OSQUERY_VERSION_FLOOR or newer)..."

  case $OS in
    debian)
      # Modern apt key handling — apt-key is deprecated since Debian 11, removed
      # in Debian 13. Drop the GPG key into /etc/apt/keyrings/ and reference it
      # via signed-by= in the sources.list.d entry. Ensure gnupg + curl are
      # present first; minimal Debian images don't ship them.
      apt-get update -qq
      # python3 is required by the sync script (JSON envelope assembly), and
      # minimal Debian images / containers do not ship it. Without it
      # threatclaw-agent-sync crashes on the very first run with
      # "python3: command not found" and the agent never registers.
      apt-get install -y -qq --no-install-recommends gnupg curl ca-certificates python3
      install -d -m 0755 /etc/apt/keyrings
      curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg \
        | gpg --dearmor -o /etc/apt/keyrings/osquery.gpg
      chmod 0644 /etc/apt/keyrings/osquery.gpg
      echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
        > /etc/apt/sources.list.d/osquery.list
      apt-get update -qq
      apt-get install -y -qq osquery
      ;;
    redhat)
      curl -fsSL https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery >/dev/null
      yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo 2>/dev/null || \
        echo -e "[osquery]\nname=osquery\nbaseurl=https://pkg.osquery.io/rpm\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-osquery" > /etc/yum.repos.d/osquery.repo
      yum install -y osquery python3
      ;;
    macos)
      if command -v brew >/dev/null 2>&1; then
        brew install --cask osquery
      else
        warn "Homebrew not found. Install osquery manually: https://osquery.io/downloads"
        exit 1
      fi
      ;;
    *)
      warn "Unsupported OS. Install osquery manually: https://osquery.io/downloads"
      exit 1
      ;;
  esac

  log "osquery installed successfully"
}

# ── Configure osquery ──
configure_osquery() {
  local conf_dir="/etc/osquery"
  local conf_file="$conf_dir/osquery.conf"
  local flags_file="$conf_dir/osquery.flags"

  mkdir -p "$conf_dir"

  log "Configuring osquery as ThreatClaw Agent..."

  # Main config — scheduled queries for ThreatClaw
  cat > "$conf_file" << 'OSQUERY_CONF'
{
  "options": {
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_events": "false",
    "events_expiry": "3600",
    "schedule_splay_percent": "10",
    "host_identifier": "hostname"
  },
  "schedule": {
    "software_linux": {
      "query": "SELECT name, version, source FROM deb_packages UNION SELECT name, version, source FROM rpm_packages;",
      "interval": 3600,
      "description": "Software inventory (hourly)"
    },
    "software_windows": {
      "query": "SELECT name, version FROM programs;",
      "interval": 3600,
      "platform": "windows",
      "description": "Software inventory Windows (hourly)"
    },
    "process_connections": {
      "query": "SELECT p.name, p.path, s.remote_address, s.remote_port, s.local_port, s.state FROM process_open_sockets s JOIN processes p ON s.pid = p.pid WHERE s.remote_address != '' AND s.remote_address != '127.0.0.1' AND s.remote_address != '::1' AND s.state = 'ESTABLISHED';",
      "interval": 300,
      "description": "Active network connections by process (5min)"
    },
    "listening_ports": {
      "query": "SELECT l.port, l.protocol, l.address, p.name as process_name, p.path FROM listening_ports l LEFT JOIN processes p ON l.pid = p.pid;",
      "interval": 300,
      "description": "Listening ports (5min)"
    },
    "logged_in_users": {
      "query": "SELECT user, tty, host, type, time FROM logged_in_users;",
      "interval": 300,
      "description": "Currently logged in users (5min)"
    },
    "os_version": {
      "query": "SELECT name, version, major, minor, build, platform FROM os_version;",
      "interval": 86400,
      "description": "OS version (daily)"
    },
    "system_info": {
      "query": "SELECT hostname, cpu_brand, cpu_physical_cores, physical_memory, hardware_vendor, hardware_model FROM system_info;",
      "interval": 86400,
      "description": "Hardware info (daily)"
    },
    "users": {
      "query": "SELECT uid, gid, username, shell, directory FROM users WHERE shell != '/usr/sbin/nologin' AND shell != '/bin/false';",
      "interval": 3600,
      "description": "Local users with login shell (hourly)"
    },
    "crontab": {
      "query": "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab;",
      "interval": 3600,
      "description": "Crontab entries (hourly)"
    },
    "authorized_keys": {
      "query": "SELECT uid, algorithm, comment, key_file FROM authorized_keys;",
      "interval": 3600,
      "description": "SSH authorized keys (hourly)"
    },
    "interface_details": {
      "query": "SELECT interface, mac, type, mtu FROM interface_details WHERE mac != '00:00:00:00:00:00';",
      "interval": 3600,
      "description": "Network interfaces (hourly)"
    },
    "interface_addresses": {
      "query": "SELECT interface, address, mask FROM interface_addresses WHERE address NOT LIKE '127.%' AND address NOT LIKE 'fe80%';",
      "interval": 3600,
      "description": "Interface IP addresses (hourly)"
    },
    "docker_containers": {
      "query": "SELECT id, name, image, status, state FROM docker_containers;",
      "interval": 600,
      "description": "Docker containers (10min)"
    }
  },
  "file_paths": {
    "critical_linux": [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/sudoers",
      "/etc/ssh/sshd_config",
      "/etc/crontab",
      "/etc/hosts",
      "/etc/resolv.conf",
      "/root/.ssh/authorized_keys"
    ]
  },
  "events": {
    "disable_subscribers": ["user_events"]
  }
}
OSQUERY_CONF

  # Flags file
  cat > "$flags_file" << OSQUERY_FLAGS
--disable_watchdog=false
--watchdog_memory_limit=200
--watchdog_utilization_limit=3
--enable_file_events=true
--enable_process_events=true
OSQUERY_FLAGS

  log "osquery configuration written to $conf_file"
}

# ── Create ThreatClaw Agent sync script ──
create_sync_script() {
  local script="/usr/local/bin/threatclaw-agent-sync"
  local tc_url="$TC_URL"
  local tc_token="$TC_TOKEN"
  local agent_id="$AGENT_ID"

  cat > "$script" << SYNCEOF
#!/usr/bin/env bash
# ThreatClaw Agent — sync osquery results to ThreatClaw
# Runs every $SYNC_INTERVAL seconds via systemd timer or cron

set -euo pipefail

TC_URL="$tc_url"
TC_TOKEN="$tc_token"
AGENT_ID="$agent_id"
HOSTNAME="\$(hostname -s)"

# Run an osqueryi query and return its JSON output (or "[]" on failure).
# stderr is dropped — osquery prints harmless config-flag warnings there.
run_query() {
  osqueryi --json "\$1" 2>/dev/null || echo "[]"
}

# Each table is queried separately because mixing platform-specific tables
# (deb_packages / rpm_packages / programs) in a single UNION breaks the JSON
# output on systems where one of the tables is unavailable. Each result is
# written to a file in a temp dir: large inventories must never be passed via
# environment variables or command-line arguments, which would hit ARG_MAX and
# break the sync on hosts with many packages (the previous failure mode).
WORKDIR=\$(mktemp -d)
trap 'rm -rf "\$WORKDIR"' EXIT

run_query "SELECT name, version, 'deb' AS source FROM deb_packages;" > "\$WORKDIR/soft_deb.json"
run_query "SELECT name, version, 'rpm' AS source FROM rpm_packages;" > "\$WORKDIR/soft_rpm.json"
run_query "SELECT name, version, 'programs' AS source FROM programs;" > "\$WORKDIR/soft_prog.json"
run_query "SELECT p.name, p.path as process_path, s.remote_address, s.remote_port, s.local_port, s.state FROM process_open_sockets s JOIN processes p ON s.pid = p.pid WHERE s.remote_address != '' AND s.remote_address != '127.0.0.1' AND s.state = 'ESTABLISHED';" > "\$WORKDIR/sockets.json"
run_query "SELECT l.port, l.protocol, l.address, p.name FROM listening_ports l LEFT JOIN processes p ON l.pid = p.pid;" > "\$WORKDIR/ports.json"
run_query "SELECT uid, gid, username, shell FROM users WHERE shell NOT IN ('/usr/sbin/nologin', '/bin/false', '/sbin/nologin');" > "\$WORKDIR/users.json"
run_query "SELECT user, tty, host, type FROM logged_in_users;" > "\$WORKDIR/logins.json"
run_query "SELECT command, path FROM crontab;" > "\$WORKDIR/crontab.json"
run_query "SELECT uid, algorithm, comment, key_file FROM authorized_keys;" > "\$WORKDIR/ssh_keys.json"
run_query "SELECT name, version, platform FROM os_version;" > "\$WORKDIR/os_ver.json"
run_query "SELECT i.interface, i.mac, a.address as ip FROM interface_details i JOIN interface_addresses a ON i.interface = a.interface WHERE i.mac != '00:00:00:00:00:00' AND a.address NOT LIKE '127.%' AND a.address NOT LIKE 'fe80%' AND i.interface NOT LIKE 'docker%' AND i.interface NOT LIKE 'br-%' AND i.interface NOT LIKE 'veth%' AND i.interface NOT LIKE 'virbr%' AND i.interface NOT LIKE 'lxc%' AND i.interface NOT LIKE 'cni%' AND i.interface NOT LIKE 'flannel%';" > "\$WORKDIR/ifaces.json"

# DNS cache (Linux: read /etc/resolv.conf, not a true cache like Windows)
echo '[]' > "\$WORKDIR/dns.json"
if command -v osqueryi >/dev/null && osqueryi --json "SELECT * FROM dns_cache LIMIT 1" 2>/dev/null | grep -q name; then
  run_query "SELECT name FROM dns_cache LIMIT 200;" > "\$WORKDIR/dns.json"
fi

# Docker
echo '[]' > "\$WORKDIR/docker.json"
if command -v docker >/dev/null; then
  run_query "SELECT id, name, image, status, state FROM docker_containers;" > "\$WORKDIR/docker.json"
fi

# Assemble the final JSON in Python, reading each chunk from its file and
# writing the payload to a file — nothing large ever crosses env or argv, so
# this is safe regardless of inventory size. Each chunk is parsed in isolation
# so a malformed table only blanks itself out.
TC_WORKDIR="\$WORKDIR" TC_HOSTNAME="\$HOSTNAME" TC_AGENT_ID="\$AGENT_ID" python3 << 'PYEOF'
import json, os
workdir = os.environ["TC_WORKDIR"]
def load(fname, default):
    try:
        with open(os.path.join(workdir, fname)) as f:
            v = json.loads(f.read() or "null")
        return v if v is not None else default
    except Exception:
        return default
# Software: union of all available package sources (deb / rpm / programs).
software = []
for k in ("soft_deb.json", "soft_rpm.json", "soft_prog.json"):
    software.extend(load(k, []))
# os_version: osquery returns a list with one row.
os_rows = load("os_ver.json", [])
os_version = os_rows[0] if os_rows else {}
payload = {
    "hostname": os.environ["TC_HOSTNAME"],
    "agent_id": os.environ["TC_AGENT_ID"],
    "software": software,
    "process_open_sockets": load("sockets.json", []),
    "listening_ports": load("ports.json", []),
    "users": load("users.json", []),
    "logged_in_users": load("logins.json", []),
    "scheduled_tasks": load("crontab.json", []),
    "authorized_keys": load("ssh_keys.json", []),
    "os_version": os_version,
    "interface_details": load("ifaces.json", []),
    "dns_cache": load("dns.json", []),
    "docker_containers": load("docker.json", []),
}
with open(os.path.join(workdir, "payload.json"), "w") as f:
    json.dump(payload, f)
PYEOF

# Send to ThreatClaw — header takes precedence over query token; the query
# arg is left as a fallback for proxies that strip custom headers. The payload
# is read from a file with @, so its size never hits the argv limit either.
curl -fsSL -X POST \\
  -H "Content-Type: application/json" \\
  -H "X-Webhook-Token: \$TC_TOKEN" \\
  --data-binary @"\$WORKDIR/payload.json" \\
  "\${TC_URL}/api/tc/webhook/ingest/osquery?token=\$TC_TOKEN" \\
  --max-time 30 \\
  -k \\
  -o /dev/null -w "HTTP %{http_code}" 2>/dev/null && echo " — sync OK" || echo " — sync FAILED"
SYNCEOF

  chmod +x "$script"
  log "Sync script created at $script"
}

# ── Create systemd service + timer ──
create_service() {
  if [ "$OS" = "macos" ]; then
    # macOS: use launchd
    log "macOS: creating LaunchDaemon..."
    cat > /Library/LaunchDaemons/io.threatclaw.agent.plist << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.threatclaw.agent</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/threatclaw-agent-sync</string></array>
  <key>StartInterval</key><integer>${SYNC_INTERVAL}</integer>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
PLISTEOF
    launchctl load /Library/LaunchDaemons/io.threatclaw.agent.plist
    log "LaunchDaemon created and loaded"
    return
  fi

  # Linux: systemd
  cat > /etc/systemd/system/threatclaw-agent.service << SVCEOF
[Unit]
Description=ThreatClaw Agent — endpoint security sync
After=network-online.target osqueryd.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/threatclaw-agent-sync
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

  cat > /etc/systemd/system/threatclaw-agent.timer << TIMEREOF
[Unit]
Description=ThreatClaw Agent sync timer

[Timer]
OnBootSec=60
OnUnitActiveSec=${SYNC_INTERVAL}s
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
TIMEREOF

  systemctl daemon-reload
  systemctl enable --now osqueryd 2>/dev/null || true
  systemctl enable --now threatclaw-agent.timer

  log "Systemd timer created (every ${SYNC_INTERVAL}s)"
}

# ── Forward auth/audit logs via the host's existing rsyslog ──
#
# osquery captures inventory + process_events + file_events but does NOT
# tail /var/log/auth.log or auditd; on Linux those events live in the
# system log stream. The cleanest way to get them to ThreatClaw is to
# piggyback on the rsyslog daemon already present on every Debian /
# Ubuntu / RHEL endpoint — drop a single file in /etc/rsyslog.d/ and the
# auth/sudo/audit stream is forwarded to TC's syslog ingest port (514).
#
# Why a custom template (TCForwardFmt) rather than the rsyslog default:
# journald-sourced messages re-emitted by rsyslog can drop the hostname
# field, which the server-side fluent-bit RFC3164 parser then fills with
# the syslogtag (= the process name). All events end up attributed to
# "systemd" / "kernel" / "containerd" instead of the real host. Forcing
# %HOSTNAME% explicitly avoids that.
configure_rsyslog_forwarder() {
  # Extract bare host first so the warning below points at a real URL.
  # TC_URL may be `https://10.0.0.1`, `https://10.0.0.1:8443`, or `host`.
  # ${TC_URL%:*} drops everything from the first `:` and produced
  # "https:514" in the warning when no port was set — strip scheme + port
  # explicitly with sed instead.
  local tc_host
  tc_host=$(echo "$TC_URL" | sed -E 's|^https?://||; s|:[0-9]+.*$||; s|/.*$||')

  if ! command -v rsyslogd >/dev/null 2>&1; then
    warn "rsyslog not installed - auth/audit logs won't be forwarded"
    warn "Install rsyslog (apt install rsyslog) or wire your own forwarder to ${tc_host}:514"
    return
  fi

  local conf="/etc/rsyslog.d/99-threatclaw.conf"
  log "Configuring rsyslog forwarder -> ${tc_host}:514"
  cat > "$conf" << RSYSLOG_CONF
# ThreatClaw log forwarder - auto-generated by install-agent.sh
# Rollback: rm $conf && systemctl restart rsyslog
\$template TCForwardFmt,"<%pri%>%timegenerated:1:15:date-rfc3164% %HOSTNAME% %syslogtag%%msg%\n"
auth,authpriv.* @@${tc_host}:514;TCForwardFmt
*.* @@${tc_host}:514;TCForwardFmt
RSYSLOG_CONF

  systemctl restart rsyslog 2>/dev/null && log "rsyslog restarted" || warn "Failed to restart rsyslog"
}

# ── auditd rules for FIM on critical files + root execve ──
#
# Best-effort: if auditd is present we drop a rule file that watches the
# files the SOC actually cares about (passwd/shadow/sudoers/sshd_config)
# and traces every execve under uid 0. If auditd is absent we skip
# silently - osquery already does process events.
configure_auditd() {
  if ! command -v auditctl >/dev/null 2>&1; then
    return
  fi
  local rules="/etc/audit/rules.d/99-threatclaw.rules"
  log "Configuring auditd rules -> $rules"
  cat > "$rules" << 'AUDIT_RULES'
# ThreatClaw auditd rules - auto-generated by install-agent.sh
# Rollback: rm /etc/audit/rules.d/99-threatclaw.rules && augenrules --load
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec
AUDIT_RULES
  if augenrules --load 2>/dev/null; then
    systemctl restart auditd 2>/dev/null && log "auditd reloaded" || warn "auditd reload returned non-zero"
  else
    warn "augenrules --load failed - rules dropped but not applied"
  fi
}

# ── Main ──
main() {
  info "ThreatClaw Agent Installer"
  info "TC URL:    $TC_URL"
  info "Agent ID:  $AGENT_ID"
  echo ""

  install_osquery
  configure_osquery
  create_sync_script
  create_service
  configure_rsyslog_forwarder
  configure_auditd

  echo ""
  log "Installation complete!"
  log "Agent ID: $AGENT_ID"
  log "The agent will sync to ThreatClaw every ${SYNC_INTERVAL} seconds."
  log "Check status: systemctl status threatclaw-agent.timer"
  log "Manual sync:  /usr/local/bin/threatclaw-agent-sync"
  echo ""

  # First sync
  info "Running first sync..."
  /usr/local/bin/threatclaw-agent-sync || warn "First sync failed (TC may not be reachable yet)"
}

main
