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
# Secret d'enrôlement par-agent (recommandé). Si présent, le poste s'enrôle et
# reçoit un token UNIQUE lié à son identité — plus de token de flotte partagé.
TC_ENROLL_SECRET="${TC_ENROLL_SECRET:-}"
# FRONT-H2 — Épinglage TLS (clé publique). Le serveur TC est self-signed : sans
# épinglage, `curl -k` accepte N'IMPORTE QUEL certificat → un MITM peut se faire
# passer pour le serveur. Si `--pin sha256//BASE64` (ou TC_PIN) est fourni, on
# vérifie la clé du serveur au premier contact (aucun TOFU). Sinon on CAPTURE la
# clé à l'install (TOFU) et on épingle tous les échanges suivants — un MITM
# ultérieur (menace réaliste hors fenêtre d'install) est alors rejeté.
TC_PIN="${TC_PIN:-}"
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
    --url)                 TC_URL="$2"; shift 2 ;;
    --token)               TC_TOKEN="$2"; shift 2 ;;
    --token-file)          TC_TOKEN="$(cat "$2")"; shift 2 ;;
    --enroll-secret)       TC_ENROLL_SECRET="$2"; shift 2 ;;
    --enroll-secret-file)  TC_ENROLL_SECRET="$(cat "$2")"; shift 2 ;;
    --pin)                 TC_PIN="$2"; shift 2 ;;
    --id)                  AGENT_ID="$2"; shift 2 ;;
    --help)
      echo "Usage: install-agent.sh --url https://TC:8445 --enroll-secret SECRET [--pin sha256//BASE64]"
      echo "   (legacy) install-agent.sh --url https://TC:8445 --token TOKEN [--id AGENT_ID]"
      echo "  --pin  épingle la clé publique TLS du serveur (anti-MITM). Sans --pin,"
      echo "         la clé est capturée à l'install (TOFU) et affichée pour un futur --pin."
      exit 0 ;;
    *) shift ;;
  esac
done

if [ -z "$TC_URL" ]; then
  warn "Missing --url (ThreatClaw instance URL)"
  echo "Usage: curl -fsSL get.threatclaw.io/agent | sudo bash -s -- --url https://TC_IP:8445 --token TOKEN"
  exit 1
fi

if [ -z "$TC_ENROLL_SECRET" ] && [ -z "$TC_TOKEN" ]; then
  warn "Missing --enroll-secret (recommended) or --token"
  echo "Get the enrollment secret from the ThreatClaw dashboard (Agents), then:"
  echo "  curl -fsSL get.threatclaw.io/agent | sudo bash -s -- --url https://TC_IP:8445 --enroll-secret SECRET"
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

# ── FRONT-H2 — Résolution de l'épinglage TLS (clé publique du serveur) ──
# Calcule le pin SPKI (SHA-256 de la SubjectPublicKeyInfo au format DER, base64)
# du certificat présenté par le serveur — exactement la formule attendue par
# `curl --pinnedpubkey`. Ce pin est ensuite exigé sur CHAQUE appel (enroll, ping,
# manifest, ingest). `curl` vérifie `--pinnedpubkey` MÊME avec `-k` : on garde
# `-k` pour ignorer la chaîne CA (cert self-signed) tout en imposant la clé
# exacte. Un MITM présentant un autre certificat (autre clé) est donc rejeté.
compute_server_pin() {
  local host="$1" port="$2"
  echo | openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null \
    | openssl x509 -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary 2>/dev/null \
    | openssl base64 2>/dev/null | tr -d '\n'
}

TC_CURL_PIN=""   # Options curl d'épinglage, injectées dans chaque appel (vide = repli -k).
# host:port depuis TC_URL (https://IP:8445 → IP 8445 ; sans port → 443).
tc_pin_hostport=$(printf '%s' "$TC_URL" | sed -E 's|^https?://||; s|/.*$||')
case "$tc_pin_hostport" in
  *:*) tc_pin_host="${tc_pin_hostport%%:*}"; tc_pin_port="${tc_pin_hostport##*:}" ;;
  *)   tc_pin_host="$tc_pin_hostport"; tc_pin_port=443 ;;
esac
TC_PIN="${TC_PIN#sha256//}"   # accepte `sha256//BASE64` ou `BASE64`.
if command -v openssl >/dev/null 2>&1; then
  tc_actual_pin=$(compute_server_pin "$tc_pin_host" "$tc_pin_port")
  if [ -z "$tc_actual_pin" ]; then
    warn "TLS pinning: impossible de lire le certificat de $tc_pin_host:$tc_pin_port. Repli sur -k (pas de protection MITM) — vérifiez l'URL/port."
  elif [ -n "$TC_PIN" ]; then
    # Pin attendu fourni → vérification stricte, aucun TOFU.
    if [ "$tc_actual_pin" = "$TC_PIN" ]; then
      TC_CURL_PIN="--pinnedpubkey sha256//$TC_PIN"
      log "TLS pinning: clé serveur vérifiée (pin fourni)."
    else
      warn "TLS pinning: MISMATCH — la clé de $tc_pin_host:$tc_pin_port ne correspond PAS au --pin attendu."
      warn "  attendu : sha256//$TC_PIN"
      warn "  reçu    : sha256//$tc_actual_pin"
      warn "Interception possible (MITM). Rien n'a été installé."; exit 1
    fi
  else
    # Aucun pin fourni → TOFU : capture la clé actuelle et l'épingle pour la suite.
    TC_PIN="$tc_actual_pin"
    TC_CURL_PIN="--pinnedpubkey sha256//$TC_PIN"
    info "TLS pinning: clé serveur capturée (TOFU) — sha256//$TC_PIN"
    info "  Pour supprimer le TOFU, relancez avec: --pin sha256//$TC_PIN  (idéal en GPO/masse)"
  fi
else
  warn "TLS pinning: openssl introuvable — repli sur -k (pas de protection MITM). Installez openssl pour épingler."
fi

# ── Pre-flight ──
# Verify the server is reachable AND the token is valid BEFORE touching the
# system, so a wrong URL/port (often :8445, not 443) or a bad token fails fast
# instead of leaving a half-configured agent that silently never reports.
# -k matches the sync script (self-signed cert); this checks reachability +
# token, not cert validity.
TC_CREDS="/etc/threatclaw-agent/agent.env"
if [ -n "$TC_ENROLL_SECRET" ]; then
  # ── Enrôlement par-agent (idempotent) ──
  # Le poste s'enrôle et reçoit un token UNIQUE lié à son agent_id (généré côté
  # serveur) et son hostname. Remplace le token de flotte partagé (findings
  # ING-C1/H6). L'enrôlement fait aussi office de pré-flight : un succès prouve
  # la joignabilité ET la validité du secret. -k = cert self-signed.
  #
  # IDEMPOTENCE (déploiement GPO / ré-exécution) : si le poste possède déjà des
  # identifiants enrôlés (fichier root-only $TC_CREDS), on les RÉUTILISE au lieu
  # de créer une nouvelle identité à chaque exécution. TC_FORCE_ENROLL=1 force un
  # nouvel enrôlement (rotation d'identité).
  need_enroll=1
  if [ -z "${TC_FORCE_ENROLL:-}" ] && [ -f "$TC_CREDS" ]; then
    # shellcheck disable=SC1090
    . "$TC_CREDS" 2>/dev/null || true
    if [ -n "${AGENT_ID:-}" ] && [ -n "${TC_TOKEN:-}" ]; then
      need_enroll=0
      log "Already enrolled — reusing identity agent_id=$AGENT_ID (set TC_FORCE_ENROLL=1 to re-enroll)"
    fi
  fi
  if [ "$need_enroll" = "1" ]; then
    info "Enrolling this host with ThreatClaw at $TC_URL ..."
    enroll_hostname="$(hostname -s)"
    enroll_resp=$(curl -sk $TC_CURL_PIN --max-time 15 -w '\n%{http_code}' \
      -X POST -H "X-Enroll-Secret: $TC_ENROLL_SECRET" -H "Content-Type: application/json" \
      --data "{\"hostname\":\"${enroll_hostname}\",\"platform\":\"linux\"}" \
      "${TC_URL}/api/tc/agent/enroll" 2>/dev/null)
    enroll_code=$(printf '%s' "$enroll_resp" | tail -n1)
    enroll_body=$(printf '%s' "$enroll_resp" | sed '$d')
    [ -n "${TC_DEBUG:-}" ] && info "DEBUG enroll: code=$enroll_code body=$enroll_body"
    if [ "$enroll_code" = "401" ]; then
      warn "Enrollment refused — invalid enroll secret (Dashboard > Agents). Nothing was installed."; exit 1
    elif [ -z "$enroll_code" ] || [ "$enroll_code" = "000" ]; then
      warn "Cannot reach ThreatClaw at $TC_URL — check the URL and PORT (often :8445, not 443) and any firewall. Nothing was installed."; exit 1
    fi
    # Parse per-key (order-independent, no jq dependency).
    AGENT_ID=$(printf '%s' "$enroll_body" | sed -n 's/.*"agent_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    TC_TOKEN=$(printf '%s' "$enroll_body" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [ -z "$AGENT_ID" ] || [ -z "$TC_TOKEN" ]; then
      warn "Enrollment response invalid (no agent_id/token): $enroll_body. Nothing was installed."; exit 1
    fi
    # Persiste l'identité (root-only 0600) → idempotence des ré-exécutions.
    ( umask 077; mkdir -p /etc/threatclaw-agent && \
      printf 'AGENT_ID=%s\nTC_TOKEN=%s\n' "$AGENT_ID" "$TC_TOKEN" > "$TC_CREDS" )
    chmod 700 /etc/threatclaw-agent 2>/dev/null || true
    chmod 600 "$TC_CREDS" 2>/dev/null || true
    log "Enrolled — agent_id=$AGENT_ID (per-agent token issued)"
  fi
else
  # ── Legacy : token de flotte partagé (déprécié — sera rejeté par la vérif
  #    stricte côté serveur tant que le poste n'est pas enrôlé). ──
  info "Pre-flight (legacy token): checking connection at $TC_URL ..."
  if [ -n "${TC_SKIP_PREFLIGHT:-}" ]; then
    warn "Pre-flight SKIPPED (TC_SKIP_PREFLIGHT set) — proceeding without checking."
    ping_code="skip"; ping_body=""
  else
    ping_resp=$(curl -sk $TC_CURL_PIN --max-time 10 -w '\n%{http_code}' \
      -X POST -H "X-Webhook-Token: $TC_TOKEN" \
      "${TC_URL}/api/tc/webhook/ping/osquery" 2>/dev/null)
    ping_code=$(printf '%s' "$ping_resp" | tail -n1)
    ping_body=$(printf '%s' "$ping_resp" | sed '$d')
  fi
  [ -n "${TC_DEBUG:-}" ] && info "DEBUG pre-flight: code=$ping_code body=$ping_body"
  if printf '%s' "$ping_body" | grep -q 'bad_token'; then
    warn "Server reachable but the webhook token is INVALID. Nothing was installed."; exit 1
  elif [ -z "$ping_code" ] || [ "$ping_code" = "000" ]; then
    warn "Cannot reach ThreatClaw at $TC_URL — check the URL and PORT and any firewall. Nothing was installed."; exit 1
  elif printf '%s' "$ping_body" | grep -q '"tc_preflight":"ok"'; then
    log "Pre-flight OK — server reachable and token valid"
  else
    warn "Server reachable; token check inconclusive — proceeding (the first sync is the real test)."
  fi
fi

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
  local tc_pin="$TC_PIN"   # FRONT-H2 — pin résolu (bare base64) propagé au sync.

  cat > "$script" << SYNCEOF
#!/usr/bin/env bash
# ThreatClaw Agent — sync osquery results to ThreatClaw
# Runs every $SYNC_INTERVAL seconds via systemd timer or cron

set -euo pipefail

TC_URL="$tc_url"
TC_TOKEN="$tc_token"
AGENT_ID="$agent_id"
HOSTNAME="\$(hostname -s)"

# FRONT-H2 — Épinglage TLS: exige la clé publique du serveur sur chaque appel.
# Vérifié par curl même avec -k (on garde -k pour le cert self-signed). Vide =
# repli sans épinglage (openssl absent à l'install).
TC_PIN="$tc_pin"
TC_CURL_PIN=""
[ -n "\$TC_PIN" ] && TC_CURL_PIN="--pinnedpubkey sha256//\$TC_PIN"

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
import json, os, hashlib, time
workdir = os.environ["TC_WORKDIR"]
STATE = "/var/lib/threatclaw/state.json"
def load(fname, default):
    try:
        with open(os.path.join(workdir, fname)) as f:
            v = json.loads(f.read() or "null")
        return v if v is not None else default
    except Exception:
        return default
# Persisted delta state: a content hash per inventory section + last full
# refresh time. Missing/corrupt -> treat as empty (first sync ships everything).
try:
    with open(STATE) as f:
        state = json.loads(f.read() or "{}")
    if not isinstance(state, dict):
        state = {}
except Exception:
    state = {}
hashes = state.get("hashes", {})
if not isinstance(hashes, dict):
    hashes = {}
now = int(time.time())
full_refresh = (now - int(state.get("last_full", 0) or 0)) > 86400  # 1x/day self-heal
# Software: union of all available package sources (deb / rpm / programs).
software = []
for k in ("soft_deb.json", "soft_rpm.json", "soft_prog.json"):
    software.extend(load(k, []))
# os_version: osquery returns a list with one row.
os_rows = load("os_ver.json", [])
os_version = os_rows[0] if os_rows else {}
# hostname/agent_id/ts are ALWAYS present = heartbeat. Volatile detection inputs
# (sockets, listening ports, dns) are ALWAYS shipped (re-checked vs threat intel
# every cycle, never delta'd). Inventory below is shipped only when its hash
# changed (or on the daily full refresh).
payload = {
    "hostname": os.environ["TC_HOSTNAME"],
    "agent_id": os.environ["TC_AGENT_ID"],
    "platform": "linux",
    "ts": now,
    "process_open_sockets": load("sockets.json", []),
    "listening_ports": load("ports.json", []),
    "dns_cache": load("dns.json", []),
}
inventory = {
    "software": software,
    "users": load("users.json", []),
    "logged_in_users": load("logins.json", []),
    "scheduled_tasks": load("crontab.json", []),
    "authorized_keys": load("ssh_keys.json", []),
    "os_version": os_version,
    "interface_details": load("ifaces.json", []),
    "docker_containers": load("docker.json", []),
}
# Web access-log delta, same discipline as the audit log below: byte offset in
# the shared state file (promoted only on a 200), capped, cut on a line boundary.
# Only the first readable path is followed — shipping nginx AND apache AND every
# vhost file would multiply the payload for no detection gain.
ACCESS_LOGS = [
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
]
ACCESS_MAX_BYTES = 2_000_000
access_off = int(state.get("access_offset", 0) or 0)
access_path = state.get("access_path") or ""
try:
    chosen = access_path if (access_path and os.path.exists(access_path)) else next(
        (p for p in ACCESS_LOGS if os.path.exists(p) and os.access(p, os.R_OK)), "")
    if chosen != access_path:      # first run, or the server changed
        access_off, access_path = 0, chosen
    if access_path:
        access_size = os.path.getsize(access_path)
        if access_size < access_off:   # rotated
            access_off = 0
        if access_size > access_off:
            with open(access_path, "rb") as f:
                f.seek(access_off)
                chunk = f.read(ACCESS_MAX_BYTES)
            cut = chunk.rfind(b"\n") + 1
            if cut > 0:
                lines = chunk[:cut].decode("utf-8", "replace").splitlines()
                if lines:
                    payload["access_log"] = lines
                access_off += cut
except OSError:
    pass  # no web server, or the log is root-only and we are not root

# Web error-log delta. Same discipline again. The value here is narrow but real:
# a segfault or worker crash on a public-facing server is what a memory-corruption
# exploit looks like from the outside, and the SigmaHQ apache/nginx rules match it.
ERROR_LOGS = [
    "/var/log/nginx/error.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/error_log",
]
error_off = int(state.get("error_offset", 0) or 0)
error_path = state.get("error_path") or ""
try:
    chosen_err = error_path if (error_path and os.path.exists(error_path)) else next(
        (p for p in ERROR_LOGS if os.path.exists(p) and os.access(p, os.R_OK)), "")
    if chosen_err != error_path:
        error_off, error_path = 0, chosen_err
    if error_path:
        error_size = os.path.getsize(error_path)
        if error_size < error_off:
            error_off = 0
        if error_size > error_off:
            with open(error_path, "rb") as f:
                f.seek(error_off)
                chunk = f.read(ACCESS_MAX_BYTES)
            cut = chunk.rfind(b"\n") + 1
            if cut > 0:
                lines = chunk[:cut].decode("utf-8", "replace").splitlines()
                if lines:
                    payload["error_log"] = lines
                error_off += cut
except OSError:
    pass

# auditd delta: ship the new bytes of the audit log so the server can parse each
# record into fields — the SigmaHQ linux/auditd rules match `type`/`a0`…/`name`/
# `exe`/`key`, which an opaque syslog line can never resolve. The offset lives in
# the same state file, so it is promoted only after a 200: a failed sync re-ships
# the exact same slice instead of losing it. Capped so a long outage cannot turn
# into a multi-megabyte POST, and cut on a line boundary so no record is split.
AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_MAX_BYTES = 2_000_000
audit_off = int(state.get("auditd_offset", 0) or 0)
try:
    audit_size = os.path.getsize(AUDIT_LOG)
    if audit_size < audit_off:      # log rotated — restart from the top
        audit_off = 0
    if audit_size > audit_off:
        with open(AUDIT_LOG, "rb") as f:
            f.seek(audit_off)
            chunk = f.read(AUDIT_MAX_BYTES)
        cut = chunk.rfind(b"\n") + 1
        if cut > 0:
            lines = chunk[:cut].decode("utf-8", "replace").splitlines()
            records = [l for l in lines if "msg=audit(" in l]
            if records:
                payload["auditd"] = records
            audit_off += cut
except OSError:
    pass  # auditd absent or the log unreadable — nothing to ship, not an error

new_hashes = dict(hashes)
for name, val in inventory.items():
    canon = json.dumps(val, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    if full_refresh or new_hashes.get(name) != h:
        payload[name] = val
        new_hashes[name] = h
last_full = now if full_refresh else int(state.get("last_full", 0) or 0)
with open(os.path.join(workdir, "payload.json"), "w") as f:
    json.dump(payload, f)
# Candidate state — promoted to STATE by the sync script only after a 200, so a
# failed sync re-sends the exact same delta next cycle (nothing lost).
with open(os.path.join(workdir, "state_new.json"), "w") as f:
    json.dump({"hashes": new_hashes, "last_full": last_full, "auditd_offset": audit_off,
               "access_offset": access_off, "access_path": access_path,
               "error_offset": error_off, "error_path": error_path}, f)
PYEOF

# Negotiate gzip: only compress if the server advertises accepts_gzip in its
# manifest (version-skew safe). Substring match avoids a jq dependency.
TC_ACCEPTS_GZIP=false
MANIFEST=\$(curl -fsSL -k \$TC_CURL_PIN --max-time 10 -H "X-Webhook-Token: \$TC_TOKEN" -H "X-Agent-Id: \$AGENT_ID" \\
  "\${TC_URL}/api/tc/agent/manifest?platform=linux&token=\$TC_TOKEN" 2>/dev/null || echo "")
case "\$MANIFEST" in
  *'"accepts_gzip":true'*|*'"accepts_gzip": true'*) TC_ACCEPTS_GZIP=true ;;
esac

# Send to ThreatClaw — header takes precedence over query token; the query arg
# is a fallback for proxies that strip custom headers. The payload is read from
# a file with @, so its size never hits the argv limit. gzip if negotiated, with
# a clear plaintext fallback. State is promoted only after a 200 (no lost delta).
TC_PAYLOAD="\$WORKDIR/payload.json"
TC_ENC_HEADER=""
if [ "\$TC_ACCEPTS_GZIP" = "true" ] && command -v gzip >/dev/null 2>&1; then
  if gzip -c "\$WORKDIR/payload.json" > "\$WORKDIR/payload.json.gz" 2>/dev/null; then
    TC_PAYLOAD="\$WORKDIR/payload.json.gz"
    TC_ENC_HEADER="-H Content-Encoding:gzip"
  fi
fi
TC_HTTP=\$(curl -sk \$TC_CURL_PIN -o /dev/null -w '%{http_code}' -X POST \\
  -H "Content-Type: application/json" \\
  -H "X-Webhook-Token: \$TC_TOKEN" \\
  -H "X-Agent-Id: \$AGENT_ID" \\
  \$TC_ENC_HEADER \\
  --data-binary @"\$TC_PAYLOAD" \\
  --max-time 120 \\
  "\${TC_URL}/api/tc/webhook/ingest/osquery?token=\$TC_TOKEN" 2>/dev/null || echo "000")
if [ "\$TC_HTTP" = "200" ]; then
  install -d -m 0700 /var/lib/threatclaw 2>/dev/null || true
  cp "\$WORKDIR/state_new.json" /var/lib/threatclaw/state.json 2>/dev/null || true
  echo "HTTP 200 (gzip=\$TC_ACCEPTS_GZIP) — sync OK"
else
  echo "HTTP \$TC_HTTP — sync FAILED (state preserved)"
fi
SYNCEOF

  chmod +x "$script"
  # Delta-sync state dir (hashes + last full refresh). 0700: root-only.
  install -d -m 0700 /var/lib/threatclaw
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
  log "Uninstall:    curl -fsSL get.threatclaw.io/agent/uninstall | sudo bash"
  log "              (removes the systemd units, the agent script, and osquery)"
  log "              set TC_KEEP_OSQUERY=1 to keep osquery installed"
  echo ""

  # First sync
  info "Running first sync..."
  /usr/local/bin/threatclaw-agent-sync || warn "First sync failed (TC may not be reachable yet)"
}

main
