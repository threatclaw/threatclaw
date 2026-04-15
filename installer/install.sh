#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# ThreatClaw Installer
#
# Usage:
#   curl -fsSL https://get.threatclaw.io | sudo bash
#
# Options:
#   --data DIR          Install directory (default: /opt/threatclaw)
#   --port PORT         Dashboard port (default: 3001)
#   --docker-data DIR   Docker data-root override (for custom partitioning)
#   --hostname NAME     Hostname for TLS certificate (default: threatclaw.local)
#   --clean             Wipe all data and reinstall fresh (keeps Docker image cache)
#   --uninstall         Remove ThreatClaw completely (including Docker images)
#   --update            Pull latest images and restart
#   --status            Show service status
#   --yes               Skip confirmation prompt
#
# Disk requirements:
#   Docker images + AI models + DB = ~30GB minimum
#   Docker stores images in /var/lib/docker by default.
#   If /var is on a small partition (common with LVM), use --docker-data
#   to point Docker storage to a partition with enough space:
#
#     curl -fsSL https://get.threatclaw.io | sudo bash -s -- --docker-data /home/docker
#
# This script is idempotent — safe to run multiple times.
# ──────────────────────────────────────────────────────────────────────────────
set -eo pipefail

# ── Constants ────────────────────────────────────────────────────────────────
readonly TC_VERSION="1.0.0-beta"
readonly DEFAULT_DIR="/opt/threatclaw"
readonly REPO_RAW="https://raw.githubusercontent.com/threatclaw/threatclaw/main"
readonly LOG_FILE="/var/log/threatclaw-install.log"

# ── Colors ───────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# ── Flags ────────────────────────────────────────────────────────────────────
TC_DIR="$DEFAULT_DIR"
TC_PORT=3001
TC_CORE_PORT=3000
TC_DOCKER_DATA=""
TC_HOSTNAME="threatclaw.local"
TC_HTTPS_PORT=443
TC_HTTP_PORT=80
TC_DEPLOY_MODE=""          # standalone | external-proxy | custom-port (auto-detected)
FLAG_UNINSTALL=false
FLAG_UPDATE=false
FLAG_STATUS=false
FLAG_CLEAN=false
FLAG_YES=false

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)         TC_PORT="$2"; shift 2 ;;
    --data)         TC_DIR="$2"; shift 2 ;;
    --docker-data)  TC_DOCKER_DATA="$2"; shift 2 ;;
    --hostname)     TC_HOSTNAME="$2"; shift 2 ;;
    --uninstall)    FLAG_UNINSTALL=true; shift ;;
    --update)       FLAG_UPDATE=true; shift ;;
    --status)       FLAG_STATUS=true; shift ;;
    --clean)        FLAG_CLEAN=true; shift ;;
    --yes)          FLAG_YES=true; shift ;;
    *)              shift ;;
  esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────
log_info()  { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_error() { echo -e "${RED}[x]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null >&2; }
log_step()  { echo -e "${CYAN}[>]${NC} ${BOLD}$*${NC}" | tee -a "$LOG_FILE" 2>/dev/null; }

generate_password() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}" || true; }

# ── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
  echo -e ""
  echo -e "${RED}  ╔════════════════════════════════════════╗${NC}"
  echo -e "${RED}  ║        ThreatClaw  v${TC_VERSION}        ║${NC}"
  echo -e "${RED}  ║   Autonomous Cybersecurity Agent       ║${NC}"
  echo -e "${RED}  ╚════════════════════════════════════════╝${NC}"
  echo ""
}

# ── Status ───────────────────────────────────────────────────────────────────
cmd_status() {
  if [ ! -d "$TC_DIR" ]; then
    log_error "ThreatClaw not installed at $TC_DIR"
    exit 1
  fi
  cd "$TC_DIR"
  echo ""
  docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null
  echo ""
  local ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo -e "  Dashboard: ${GREEN}http://${ip:-localhost}:${TC_PORT}${NC}"
  echo ""
}

# ── Uninstall ────────────────────────────────────────────────────────────────
cmd_uninstall() {
  log_step "Uninstalling ThreatClaw..."

  # Stop and remove containers via compose (preferred)
  if [ -d "$TC_DIR" ]; then
    cd "$TC_DIR"
    if [ -f "docker-compose.yml" ]; then
      log_info "Stopping containers..."
      docker compose down -v --remove-orphans 2>/dev/null || docker-compose down -v --remove-orphans 2>/dev/null || true
    fi
    cd /
  fi

  # Fallback: stop containers matching the compose project name
  local project="threatclaw"
  local containers
  containers=$(docker ps -a --filter "label=com.docker.compose.project=${project}" --format "{{.ID}}" 2>/dev/null) || true
  if [ -n "$containers" ]; then
    log_info "Removing remaining containers..."
    echo "$containers" | xargs -r docker rm -f 2>/dev/null || true
  fi

  # Remove project volumes
  local volumes
  volumes=$(docker volume ls --filter "label=com.docker.compose.project=${project}" --format "{{.Name}}" 2>/dev/null) || true
  if [ -n "$volumes" ]; then
    log_info "Removing volumes..."
    echo "$volumes" | xargs -r docker volume rm -f 2>/dev/null || true
  fi

  # Remove ThreatClaw images — only ghcr.io/threatclaw/* (safe, unique to us)
  log_info "Removing ThreatClaw images..."
  for img in ghcr.io/threatclaw/core ghcr.io/threatclaw/dashboard ghcr.io/threatclaw/db ghcr.io/threatclaw/ml-engine; do
    docker rmi -f "$img" 2>/dev/null || true
  done

  # Remove shared images ONLY if no other container uses them
  for img in ollama/ollama fluent/fluent-bit projectdiscovery/nuclei aquasec/trivy; do
    local in_use
    in_use=$(docker ps -a --filter "ancestor=$img" --format "{{.ID}}" 2>/dev/null) || true
    if [ -z "$in_use" ]; then
      docker rmi -f "$img" 2>/dev/null || true
    else
      log_info "Keeping $img — used by other containers"
    fi
  done

  # No docker image prune — could remove unrelated images on shared servers

  # Remove data directory
  if [ -d "$TC_DIR" ]; then
    rm -rf "$TC_DIR"
    log_info "ThreatClaw removed from $TC_DIR"
  else
    log_warn "No data directory found at $TC_DIR"
  fi

  log_info "Uninstall complete. Docker and system packages were not removed."
}

# ── Clean reinstall ─────────────────────────────────────────────────────────
cmd_clean() {
  log_step "Clean reinstall — wiping data but keeping Docker image cache..."

  if [ -d "$TC_DIR" ]; then
    cd "$TC_DIR"
    if [ -f "docker-compose.yml" ]; then
      log_info "Stopping containers and removing volumes..."
      docker compose down -v --remove-orphans 2>/dev/null || docker-compose down -v --remove-orphans 2>/dev/null || true
    fi
    cd /

    # Remove config files but not Docker images (they speed up reinstall)
    rm -rf "$TC_DIR"
    log_info "Data wiped from $TC_DIR (Docker images kept for faster reinstall)"
  else
    log_info "No existing install at $TC_DIR — proceeding with fresh install"
  fi

  # Continue with normal install (don't exit)
}

# ── Update ───────────────────────────────────────────────────────────────────
cmd_update() {
  log_step "Updating ThreatClaw..."
  cd "$TC_DIR"

  # Re-download compose + config files (picks up new services, DNS fixes, etc.)
  log_info "Downloading latest configuration..."
  curl -fsSL "${REPO_RAW}/docker/docker-compose.yml" -o docker-compose.yml
  curl -fsSL "${REPO_RAW}/docker/.env.example" -o .env.example
  curl -fsSL "${REPO_RAW}/docker/fluent-bit/fluent-bit.conf" -o fluent-bit/fluent-bit.conf 2>/dev/null || true
  curl -fsSL "${REPO_RAW}/docker/fluent-bit/parsers.conf" -o fluent-bit/parsers.conf 2>/dev/null || true

  # Pull latest images + force-recreate containers with new config
  log_info "Pulling latest images..."
  docker compose pull 2>/dev/null || docker-compose pull 2>/dev/null
  docker compose up -d --force-recreate 2>/dev/null || docker-compose up -d --force-recreate 2>/dev/null
  log_info "ThreatClaw updated to latest"
}

# ── Docker storage relocation ────────────────────────────────────────────────
relocate_docker_storage() {
  local new_root="${1:-${TC_DIR}/docker-data}"
  local daemon_json="/etc/docker/daemon.json"

  # Skip if already relocated
  if [ -f "$daemon_json" ] && grep -q "$new_root" "$daemon_json" 2>/dev/null; then
    log_info "Docker storage already at $new_root"
    return
  fi

  mkdir -p "$new_root"

  # Stop Docker
  systemctl stop docker 2>/dev/null || true
  systemctl stop docker.socket 2>/dev/null || true

  # Move existing data if any
  if [ -d /var/lib/docker ] && [ "$(du -sm /var/lib/docker 2>/dev/null | awk '{print $1}')" -gt 10 ]; then
    log_info "Moving existing Docker data to $new_root (this may take a moment)..."
    rsync -a /var/lib/docker/ "$new_root/" 2>/dev/null || cp -a /var/lib/docker/* "$new_root/" 2>/dev/null || true
  fi

  # Configure Docker daemon
  if [ -f "$daemon_json" ]; then
    # Merge with existing config using python/jq if available
    if command -v python3 &>/dev/null; then
      python3 -c "
import json
with open('$daemon_json') as f: cfg = json.load(f)
cfg['data-root'] = '$new_root'
with open('$daemon_json', 'w') as f: json.dump(cfg, f, indent=2)
" 2>/dev/null
    else
      # Fallback: backup and overwrite
      cp "$daemon_json" "${daemon_json}.bak"
      echo "{\"data-root\": \"$new_root\"}" > "$daemon_json"
    fi
  else
    mkdir -p /etc/docker
    echo "{\"data-root\": \"$new_root\"}" > "$daemon_json"
  fi

  # Restart Docker
  systemctl start docker
  log_info "Docker storage relocated to $new_root"
}

# ── Preflight ────────────────────────────────────────────────────────────────
check_requirements() {
  log_step "Checking requirements..."

  # Root check
  if [ "$(id -u)" -ne 0 ]; then
    log_error "Please run as root: sudo bash install.sh"
    exit 1
  fi

  # OS check
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    log_info "OS: ${PRETTY_NAME:-$ID}"
  fi

  # Docker
  if ! command -v docker &>/dev/null; then
    log_warn "Docker not found — installing..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    log_info "Docker installed"
  else
    log_info "Docker: $(docker --version | cut -d' ' -f3 | tr -d ',')"
  fi

  # Docker Compose
  if docker compose version &>/dev/null; then
    log_info "Compose: $(docker compose version --short)"
  else
    log_error "Docker Compose not found. Update Docker or install compose plugin."
    exit 1
  fi

  # RAM
  local ram_gb=$(free -g | awk '/^Mem:/{print $2}')
  if [ "${ram_gb:-0}" -lt 8 ]; then
    log_warn "RAM: ${ram_gb}GB — minimum 16GB recommended for AI models"
  else
    log_info "RAM: ${ram_gb}GB"
  fi

  # ── Disk layout analysis ──
  # Docker images (~5GB) + AI models (~18GB) + DB + logs = ~30GB minimum
  # Two locations matter:
  #   1. Install dir (--data): config files + Ollama models volume
  #   2. Docker data-root (/var/lib/docker by default): container images + layers

  log_step "Analyzing disk layout..."

  # Show partition summary for visibility
  log_info "Partition layout:"
  df -h --output=target,size,avail,pcent 2>/dev/null | grep -vE "tmpfs|udev|efi|boot$" | head -10 | while read -r line; do
    echo "       $line"
  done

  # Check install directory
  local install_part=$(df -BG "${TC_DIR%/*}" 2>/dev/null | tail -1)
  local install_free=$(echo "$install_part" | awk '{print $4}' | tr -d 'G')
  local install_mount=$(echo "$install_part" | awk '{print $6}')

  if [ "${install_free:-0}" -lt 15 ]; then
    log_warn "Install dir: ${install_free}GB free at ${install_mount} (${TC_DIR}) — need 30GB+"

    # Try to find a better partition automatically
    local best_mount="" best_free=0
    while IFS= read -r line; do
      local mfree=$(echo "$line" | awk '{print $4}' | tr -d 'G')
      local mpoint=$(echo "$line" | awk '{print $6}')
      if [ "${mfree:-0}" -gt "${best_free}" ] && [ "$mpoint" != "/" ] && [ "${mfree:-0}" -ge 30 ]; then
        best_free="$mfree"
        best_mount="$mpoint"
      fi
    done < <(df -BG 2>/dev/null | tail -n +2 | grep -v tmpfs)

    if [ -n "$best_mount" ]; then
      TC_DIR="${best_mount}/threatclaw"
      log_info "Redirecting install to ${TC_DIR} (${best_free}GB free)"
    else
      log_error "No partition with 30GB+ free found."
      log_error "Re-run with: curl ... | sudo bash -s -- --data /path/with/space"
      exit 1
    fi
  else
    log_info "Install dir: ${install_free}GB free at ${install_mount}"
  fi

  # Check Docker data-root (images, layers, volumes)
  local docker_root="/var/lib/docker"
  if [ -f /etc/docker/daemon.json ]; then
    local configured_root
    configured_root=$(python3 -c "import json; print(json.load(open('/etc/docker/daemon.json')).get('data-root',''))" 2>/dev/null) || true
    if [ -n "$configured_root" ]; then
      docker_root="$configured_root"
    fi
  fi

  local docker_part=$(df -BG "$docker_root" 2>/dev/null | tail -1)
  local docker_free=$(echo "$docker_part" | awk '{print $4}' | tr -d 'G')
  local docker_mount=$(echo "$docker_part" | awk '{print $6}')

  if [ -n "$TC_DOCKER_DATA" ]; then
    # Explicit --docker-data flag: respect it
    log_info "Docker data-root: --docker-data ${TC_DOCKER_DATA} (user override)"
    relocate_docker_storage "$TC_DOCKER_DATA"
  elif [ "${docker_free:-999}" -lt 20 ]; then
    # /var too small — auto-relocate to install dir
    log_warn "Docker storage: only ${docker_free}GB free at ${docker_mount} (${docker_root})"
    local new_docker="${TC_DIR}/docker-data"
    log_info "Relocating Docker data-root to ${new_docker}..."
    relocate_docker_storage "$new_docker"
  else
    log_info "Docker storage: ${docker_free}GB free at ${docker_mount} (${docker_root})"
  fi
}

# ── Detect existing reverse proxy ────────────────────────────────────────────
detect_proxy() {
  # Skip detection if --yes (non-interactive) — default to standalone or custom-port
  if ! ss -tlnp 2>/dev/null | grep -q ':443 '; then
    TC_DEPLOY_MODE="standalone"
    TC_HTTPS_PORT=443
    TC_HTTP_PORT=80
    log_info "Port 443 available — HTTPS reverse proxy on port 443"
    return
  fi

  # Port 443 is in use — identify what's using it
  local existing
  existing=$(ss -tlnp 2>/dev/null | grep ':443 ' | grep -oP 'users:\(\("\K[^"]+' | head -1)
  existing="${existing:-unknown}"

  log_warn "Port 443 already in use by: ${existing}"

  if $FLAG_YES; then
    # Non-interactive mode — use port 8443 automatically
    TC_DEPLOY_MODE="custom-port"
    TC_HTTPS_PORT=8443
    TC_HTTP_PORT=8880
    log_info "Non-interactive mode — using port ${TC_HTTPS_PORT} for HTTPS"
    return
  fi

  echo ""
  echo -e "  ${YELLOW}Port 443 is already used by: ${BOLD}${existing}${NC}"
  echo ""
  echo -e "  ThreatClaw needs HTTPS. Choose how to proceed:"
  echo ""
  echo -e "  ${BOLD}[1]${NC} Use your existing proxy (${existing})"
  echo -e "      ThreatClaw will expose HTTP on ports 3000/3001."
  echo -e "      You add a vhost/subdomain in your proxy."
  echo ""
  echo -e "  ${BOLD}[2]${NC} Use a different port for ThreatClaw HTTPS"
  echo -e "      ThreatClaw runs its own nginx on a custom port."
  echo ""

  local choice
  read -rp "  Choice [1/2]: " choice

  case "$choice" in
    1)
      TC_DEPLOY_MODE="external-proxy"
      log_info "Mode: external proxy — dashboard on port ${TC_PORT}, API on port ${TC_CORE_PORT}"
      ;;
    2)
      local custom_port
      read -rp "  HTTPS port [8443]: " custom_port
      TC_DEPLOY_MODE="custom-port"
      TC_HTTPS_PORT="${custom_port:-8443}"
      TC_HTTP_PORT=$((TC_HTTPS_PORT + 1))
      # Verify chosen port is free
      if ss -tlnp 2>/dev/null | grep -q ":${TC_HTTPS_PORT} "; then
        log_error "Port ${TC_HTTPS_PORT} is also in use. Try another port."
        exit 1
      fi
      log_info "Mode: custom port — HTTPS on port ${TC_HTTPS_PORT}"
      ;;
    *)
      TC_DEPLOY_MODE="external-proxy"
      log_info "Mode: external proxy (default)"
      ;;
  esac
}

# ── Download configs ─────────────────────────────────────────────────────────
download_configs() {
  log_step "Setting up ${TC_DIR}..."
  mkdir -p "$TC_DIR"
  cd "$TC_DIR"

  # Docker compose
  curl -fsSL "${REPO_RAW}/docker/docker-compose.yml" -o docker-compose.yml
  log_info "docker-compose.yml downloaded"

  # Environment file
  if [ ! -f .env ]; then
    curl -fsSL "${REPO_RAW}/docker/.env.example" -o .env
    local db_pass=$(generate_password 24)
    local auth_token=$(generate_password 64)
    sed -i "s/^TC_DASHBOARD_PORT=.*/TC_DASHBOARD_PORT=${TC_PORT}/" .env
    sed -i "s/^TC_CORE_PORT=.*/TC_CORE_PORT=${TC_CORE_PORT}/" .env
    # Docker socket GID for ephemeral skill containers
    local docker_gid=$(stat -c '%g' /var/run/docker.sock 2>/dev/null || echo "0")
    echo "DOCKER_GID=${docker_gid}" >> .env

    # Docker secrets (See ADR-039) — passwords in files, not env vars
    mkdir -p secrets
    echo -n "${db_pass}" > secrets/tc_db_password.txt
    echo -n "${auth_token}" > secrets/tc_auth_token.txt
    chmod 700 secrets
    # 644 on files (not 600) so docker compose bind-mounted secrets are
    # readable by the container user (UID 1000). The 700 parent dir still
    # blocks non-root host access — only the docker daemon (root) can enter.
    chmod 644 secrets/*.txt
    log_info "Generated Docker secrets (secrets/)"

    # TC_DB_PASSWORD is set BOTH in .env AND as a Docker secret.
    # Reason: fluent-bit 3.2 is distroless — it cannot cat /run/secrets/* and
    # requires the password as an env var (${TC_DB_PASSWORD} in compose).
    # The core service reads it from the secret file via entrypoint.sh.
    # Trade-off: password in plain-text in .env (chmod 600), but .env is
    # protected by the umask and never committed to git (gitignored).
    sed -i "s/^TC_DB_PASSWORD=.*/TC_DB_PASSWORD=${db_pass}/" .env
    sed -i "s/^TC_AUTH_TOKEN=.*/# TC_AUTH_TOKEN managed via Docker secrets (secrets\/tc_auth_token.txt)/" .env

    # HTTP_WEBHOOK_SECRET — required by core for HTTP channel authentication
    local http_webhook_secret
    http_webhook_secret=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p)
    if grep -q "^HTTP_WEBHOOK_SECRET=" .env; then
      sed -i "s/^HTTP_WEBHOOK_SECRET=.*/HTTP_WEBHOOK_SECRET=${http_webhook_secret}/" .env
    else
      echo "HTTP_WEBHOOK_SECRET=${http_webhook_secret}" >> .env
    fi

    chmod 600 .env
    log_info "Generated .env (core/auth via Docker secrets, TC_DB_PASSWORD also in .env for fluent-bit)"
  else
    log_warn ".env exists — keeping current config"
    # Migrate existing installs: create secrets from .env if not present
    if [ ! -d secrets ]; then
      mkdir -p secrets
      local existing_pass=$(grep '^TC_DB_PASSWORD=' .env 2>/dev/null | cut -d= -f2)
      local existing_token=$(grep '^TC_AUTH_TOKEN=' .env 2>/dev/null | cut -d= -f2)
      if [ -n "$existing_pass" ]; then
        echo -n "$existing_pass" > secrets/tc_db_password.txt
        echo -n "$existing_token" > secrets/tc_auth_token.txt
        chmod 700 secrets && chmod 600 secrets/*.txt
        log_info "Migrated existing credentials to Docker secrets"
      fi
    fi
  fi

  # Entrypoint (Modelfiles removed — models are created via Ollama API in entrypoint.sh)
  curl -fsSL "${REPO_RAW}/docker/entrypoint.sh" -o entrypoint.sh && chmod +x entrypoint.sh

  # Fluent Bit
  mkdir -p fluent-bit
  curl -fsSL "${REPO_RAW}/docker/fluent-bit/fluent-bit.conf" -o fluent-bit/fluent-bit.conf
  curl -fsSL "${REPO_RAW}/docker/fluent-bit/parsers.conf" -o fluent-bit/parsers.conf

  # Config files
  curl -fsSL "${REPO_RAW}/AGENT_SOUL.toml" -o AGENT_SOUL.toml
  curl -fsSL "${REPO_RAW}/threatclaw.toml" -o threatclaw.toml

  # DB Dockerfile (PostgreSQL + pgvector + AGE)
  curl -fsSL "${REPO_RAW}/docker/Dockerfile.db" -o Dockerfile.db

  # HTTPS reverse proxy (nginx + cert generation)
  if [ "$TC_DEPLOY_MODE" != "external-proxy" ]; then
    curl -fsSL "${REPO_RAW}/docker/nginx.conf" -o nginx.conf
    curl -fsSL "${REPO_RAW}/docker/generate-certs.sh" -o generate-certs.sh && chmod +x generate-certs.sh
    log_info "Nginx reverse proxy config downloaded"
  fi

  log_info "All configuration files ready"
}

# ── Start services ───────────────────────────────────────────────────────────
start_services() {
  log_step "Starting ThreatClaw..."
  cd "$TC_DIR"

  # Generate TLS certificates if using built-in nginx
  if [ "$TC_DEPLOY_MODE" != "external-proxy" ]; then
    if [ ! -f certs/server.crt ]; then
      log_step "Generating TLS certificates for ${TC_HOSTNAME}..."
      CERT_DIR="${TC_DIR}/certs" bash generate-certs.sh "$TC_HOSTNAME"
    else
      log_info "TLS certificates already exist — skipping"
    fi

    # Set HTTPS ports in .env
    echo "TC_HTTPS_PORT=${TC_HTTPS_PORT}" >> .env
    echo "TC_HTTP_PORT=${TC_HTTP_PORT}" >> .env
  fi

  # In external-proxy mode, re-expose core and dashboard ports directly
  if [ "$TC_DEPLOY_MODE" = "external-proxy" ]; then
    # Patch compose to expose ports (they're hidden behind nginx by default)
    sed -i "s/^    expose:/    ports:\n      - \"${TC_CORE_PORT}:3000\"\n    #expose:/" docker-compose.yml || true
    log_info "Core exposed on port ${TC_CORE_PORT}, Dashboard on port ${TC_PORT}"
  fi

  # Create wazuh_wazuh-net if missing — compose references it as external (optional Wazuh integration)
  if ! docker network inspect wazuh_wazuh-net >/dev/null 2>&1; then
    docker network create wazuh_wazuh-net >/dev/null
    log_info "Created empty wazuh_wazuh-net (Wazuh integration optional)"
  fi

  docker compose up -d

  log_info "Waiting for services..."
  local health_url="http://localhost:${TC_CORE_PORT}/api/health"
  # Use nginx health endpoint if available
  if [ "$TC_DEPLOY_MODE" != "external-proxy" ]; then
    health_url="https://localhost:${TC_HTTPS_PORT}/api/health"
  fi

  local attempts=0
  while [ $attempts -lt 60 ]; do
    if curl -skf "${health_url}" >/dev/null 2>&1; then
      log_info "Core is healthy"
      break
    fi
    attempts=$((attempts + 1))
    sleep 2
  done

  if [ $attempts -ge 60 ]; then
    log_warn "Startup slower than expected — services may still be initializing"
  fi

  log_info "AI models are downloading in the background (~18 GB on first boot)"
  log_info "The AI will become available automatically when download completes"
}

# ── Success ──────────────────────────────────────────────────────────────────
print_success() {
  local ip=$(hostname -I 2>/dev/null | awk '{print $1}')

  # Detect Docker data-root for display
  local docker_root="/var/lib/docker"
  if [ -f /etc/docker/daemon.json ]; then
    local dr
    dr=$(python3 -c "import json; print(json.load(open('/etc/docker/daemon.json')).get('data-root',''))" 2>/dev/null) || true
    [ -n "$dr" ] && docker_root="$dr"
  fi

  echo ""
  echo -e "  ${GREEN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "  ${GREEN}║           ThreatClaw is running!                 ║${NC}"
  echo -e "  ${GREEN}╚══════════════════════════════════════════════════╝${NC}"
  echo ""

  # Display URL based on deploy mode
  if [ "$TC_DEPLOY_MODE" = "external-proxy" ]; then
    echo -e "  Dashboard:      ${GREEN}http://${ip:-localhost}:${TC_PORT}${NC}"
    echo -e "  API:            http://${ip:-localhost}:${TC_CORE_PORT}"
    echo ""
    echo -e "  ${YELLOW}Configure your reverse proxy to forward to these ports.${NC}"
  elif [ "$TC_HTTPS_PORT" = "443" ]; then
    echo -e "  Dashboard:      ${GREEN}https://${TC_HOSTNAME}${NC}"
    echo -e "  API:            https://${TC_HOSTNAME}/api"
  else
    echo -e "  Dashboard:      ${GREEN}https://${ip:-localhost}:${TC_HTTPS_PORT}${NC}"
    echo -e "  API:            https://${ip:-localhost}:${TC_HTTPS_PORT}/api"
  fi
  echo -e "  Syslog:         ${ip:-localhost}:514 (UDP)"
  echo ""

  # Show hosts file hint for .local hostnames
  if [ "$TC_DEPLOY_MODE" != "external-proxy" ] && [[ "$TC_HOSTNAME" == *.local ]] || [[ "$TC_HOSTNAME" != *.* ]]; then
    echo -e "  ${BOLD}To access by hostname, add to your hosts file:${NC}"
    echo -e "    ${ip:-127.0.0.1}    ${TC_HOSTNAME}"
    echo ""
  fi

  # Show CA install hint for self-signed certs
  if [ "$TC_DEPLOY_MODE" != "external-proxy" ] && [ -f "${TC_DIR}/certs/ca.crt" ]; then
    echo -e "  ${BOLD}For the green padlock, install the CA certificate:${NC}"
    echo -e "    ${TC_DIR}/certs/ca.crt"
    echo ""
  fi

  echo -e "  ${BOLD}Paths:${NC}"
  echo -e "    Config & data:  ${TC_DIR}"
  echo -e "    Docker storage: ${docker_root}"
  echo -e "    Logs:           cd ${TC_DIR} && docker compose logs -f"
  echo ""
  echo -e "  ${BOLD}Next steps:${NC}"
  echo -e "    1. Open the dashboard and create your admin account"
  echo -e "    2. AI models download in the background (~18 GB, 10-15 min)"
  echo -e "    3. Configure log sources (syslog) and connectors (Wazuh, etc.)"
  echo ""
  echo -e "  ${BOLD}Commands:${NC}"
  echo "    cd ${TC_DIR} && docker compose ps          # Service status"
  echo "    cd ${TC_DIR} && docker compose logs -f      # Live logs"
  echo "    cd ${TC_DIR} && docker compose restart      # Restart"
  echo "    cd ${TC_DIR} && docker compose down         # Stop"
  echo ""
  local data_flag=""
  if [ "$TC_DIR" != "$DEFAULT_DIR" ]; then
    data_flag=" --data ${TC_DIR}"
  fi
  echo -e "  ${BOLD}Maintenance:${NC}"
  echo "    curl -fsSL https://get.threatclaw.io | sudo bash -s -- --update${data_flag}     # Update"
  echo "    curl -fsSL https://get.threatclaw.io | sudo bash -s -- --clean${data_flag}      # Fresh reinstall"
  echo "    curl -fsSL https://get.threatclaw.io | sudo bash -s -- --status${data_flag}     # Status"
  echo "    curl -fsSL https://get.threatclaw.io | sudo bash -s -- --uninstall${data_flag}  # Remove"
  echo ""
  echo -e "  ${RED}ThreatClaw${NC} — https://threatclaw.io"
  echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  print_banner

  # Handle subcommands
  if $FLAG_STATUS; then cmd_status; exit 0; fi
  if $FLAG_UNINSTALL; then cmd_uninstall; exit 0; fi
  if $FLAG_UPDATE; then cmd_update; exit 0; fi
  if $FLAG_CLEAN; then cmd_clean; fi  # Wipes data then continues with install

  # Confirmation (skip if piped or --yes)
  if ! $FLAG_YES; then
    echo -e "  ${BOLD}Install directory:${NC}  ${TC_DIR}"
    echo -e "  ${BOLD}Dashboard port:${NC}    ${TC_PORT}"
    echo -e "  ${BOLD}API port:${NC}          ${TC_CORE_PORT}"
    if [ -n "$TC_DOCKER_DATA" ]; then
      echo -e "  ${BOLD}Docker data-root:${NC}  ${TC_DOCKER_DATA}"
    fi
    echo ""
    if [ -t 0 ]; then
      read -rp "  Continue? [Y/n] " response
      case "$response" in
        [nN]*) echo "  Cancelled."; exit 0 ;;
      esac
    fi
    echo ""
  fi

  check_requirements
  detect_proxy
  download_configs
  start_services
  print_success
}

main "$@"
