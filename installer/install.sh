#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# ThreatClaw Installer
#
# Usage:
#   curl -fsSL https://get.threatclaw.io | sudo bash
#
# Options:
#   --port PORT     Dashboard port (default: 3001)
#   --data DIR      Data directory (default: /opt/threatclaw)
#   --uninstall     Remove ThreatClaw
#   --update        Pull latest images and restart
#   --status        Show service status
#   --yes           Skip confirmation prompt
#
# This script is idempotent — safe to run multiple times.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────
readonly TC_VERSION="2.2.0-beta"
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
FLAG_UNINSTALL=false
FLAG_UPDATE=false
FLAG_STATUS=false
FLAG_YES=false

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)       TC_PORT="$2"; shift 2 ;;
    --data)       TC_DIR="$2"; shift 2 ;;
    --uninstall)  FLAG_UNINSTALL=true; shift ;;
    --update)     FLAG_UPDATE=true; shift ;;
    --status)     FLAG_STATUS=true; shift ;;
    --yes)        FLAG_YES=true; shift ;;
    *)            shift ;;
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
  if [ -d "$TC_DIR" ]; then
    cd "$TC_DIR"
    docker compose down -v 2>/dev/null || docker-compose down -v 2>/dev/null || true
    cd /
    rm -rf "$TC_DIR"
    log_info "ThreatClaw removed from $TC_DIR"
  else
    log_warn "Nothing to uninstall at $TC_DIR"
  fi
}

# ── Update ───────────────────────────────────────────────────────────────────
cmd_update() {
  log_step "Updating ThreatClaw..."
  cd "$TC_DIR"
  docker compose pull 2>/dev/null || docker-compose pull 2>/dev/null
  docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null
  log_info "ThreatClaw updated to latest"
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

  # Disk
  local disk_gb=$(df -BG "${TC_DIR%/*}" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G')
  if [ "${disk_gb:-0}" -lt 10 ]; then
    log_warn "Disk: ${disk_gb}GB free — minimum 20GB recommended"
  else
    log_info "Disk: ${disk_gb}GB free"
  fi
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
    sed -i "s/^TC_DB_PASSWORD=.*/TC_DB_PASSWORD=${db_pass}/" .env
    sed -i "s/^TC_DASHBOARD_PORT=.*/TC_DASHBOARD_PORT=${TC_PORT}/" .env
    sed -i "s/^TC_CORE_PORT=.*/TC_CORE_PORT=${TC_CORE_PORT}/" .env
    log_info "Generated .env with secure password"
  else
    log_warn ".env exists — keeping current config"
  fi

  # Entrypoint + model files
  curl -fsSL "${REPO_RAW}/docker/entrypoint.sh" -o entrypoint.sh && chmod +x entrypoint.sh
  curl -fsSL "${REPO_RAW}/docker/Modelfile.threatclaw-l1" -o Modelfile.threatclaw-l1
  curl -fsSL "${REPO_RAW}/docker/Modelfile.threatclaw-l2" -o Modelfile.threatclaw-l2

  # Fluent Bit
  mkdir -p fluent-bit
  curl -fsSL "${REPO_RAW}/docker/fluent-bit/fluent-bit.conf" -o fluent-bit/fluent-bit.conf
  curl -fsSL "${REPO_RAW}/docker/fluent-bit/parsers.conf" -o fluent-bit/parsers.conf

  # Config files
  curl -fsSL "${REPO_RAW}/AGENT_SOUL.toml" -o AGENT_SOUL.toml
  curl -fsSL "${REPO_RAW}/threatclaw.toml" -o threatclaw.toml

  # DB Dockerfile (PostgreSQL + pgvector + AGE)
  curl -fsSL "${REPO_RAW}/docker/Dockerfile.db" -o Dockerfile.db

  log_info "All configuration files ready"
}

# ── Start services ───────────────────────────────────────────────────────────
start_services() {
  log_step "Starting ThreatClaw..."
  cd "$TC_DIR"

  docker compose up -d

  log_info "Waiting for services to be healthy..."
  local attempts=0
  while [ $attempts -lt 60 ]; do
    if curl -sf "http://localhost:${TC_CORE_PORT}/api/health" >/dev/null 2>&1; then
      log_info "Core is healthy"
      break
    fi
    attempts=$((attempts + 1))
    sleep 3
  done

  if [ $attempts -ge 60 ]; then
    log_warn "Core took longer than expected. Check: docker compose logs threatclaw-core"
  fi
}

# ── Success ──────────────────────────────────────────────────────────────────
print_success() {
  local ip=$(hostname -I 2>/dev/null | awk '{print $1}')

  echo ""
  echo -e "  ${GREEN}ThreatClaw is running!${NC}"
  echo ""
  echo -e "  Dashboard:  ${GREEN}http://${ip:-localhost}:${TC_PORT}${NC}"
  echo -e "  API:        http://${ip:-localhost}:${TC_CORE_PORT}"
  echo -e "  Data:       ${TC_DIR}"
  echo ""
  echo -e "  ${YELLOW}Open the dashboard to create your admin account.${NC}"
  echo -e "  AI models will download automatically on first boot (~15-20 GB)."
  echo ""
  echo "  Useful commands:"
  echo "    cd ${TC_DIR} && docker compose logs -f       # Live logs"
  echo "    cd ${TC_DIR} && docker compose restart       # Restart"
  echo "    cd ${TC_DIR} && docker compose down          # Stop"
  echo "    curl -fsSL https://get.threatclaw.io | sudo bash -s -- --update  # Update"
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

  # Confirmation
  if ! $FLAG_YES; then
    echo -e "  This will install ThreatClaw to ${BOLD}${TC_DIR}${NC}"
    echo -e "  Dashboard port: ${BOLD}${TC_PORT}${NC}"
    echo ""
    read -rp "  Continue? [Y/n] " response
    case "$response" in
      [nN]*) echo "  Cancelled."; exit 0 ;;
    esac
    echo ""
  fi

  check_requirements
  download_configs
  start_services
  print_success
}

main "$@"
