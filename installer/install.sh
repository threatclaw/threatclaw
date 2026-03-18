#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# ThreatClaw Installer
# Installs ThreatClaw on a fresh Debian 12 / Ubuntu 22.04+ VPS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/threatclaw/threatclaw/main/installer/install.sh | sudo bash
#
# Flags:
#   --uninstall   Remove ThreatClaw and all associated data
#   --update      Pull the latest version and restart services
#   --status      Show current service status
#   --no-tls      Skip self-signed TLS certificate generation
#   --yes         Skip the initial confirmation prompt
#
# This script is idempotent — safe to run multiple times.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
readonly THREATCLAW_VERSION="0.1.0"
readonly INSTALL_DIR="/opt/threatclaw"
readonly REPO_URL="https://github.com/threatclaw/threatclaw.git"
readonly SYSTEM_USER="threatclaw"
readonly SERVICE_NAME="threatclaw"
readonly COMPOSE_DIR="${INSTALL_DIR}/docker"
readonly ENV_FILE="${INSTALL_DIR}/.env"
readonly CERT_DIR="${INSTALL_DIR}/certs"
readonly LOG_FILE="/var/log/threatclaw-install.log"

# ── Colors ────────────────────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# ── Flags ─────────────────────────────────────────────────────────────────────
FLAG_UNINSTALL=false
FLAG_UPDATE=false
FLAG_STATUS=false
FLAG_NO_TLS=false
FLAG_YES=false

# ── Helper Functions ──────────────────────────────────────────────────────────

log_info() {
    echo -e "${GREEN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2
}

log_step() {
    echo -e "${CYAN}[STEP]${NC}  ${BOLD}$*${NC}" | tee -a "$LOG_FILE"
}

check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        return 1
    fi
    return 0
}

generate_password() {
    local length="${1:-32}"
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$length" || true
}

wait_for_healthy() {
    local service="$1"
    local max_attempts="${2:-60}"
    local interval="${3:-5}"
    local attempt=0

    log_info "Waiting for ${service} to become healthy..."
    while [ $attempt -lt $max_attempts ]; do
        local status
        status=$(docker compose -f "${COMPOSE_DIR}/docker-compose.yml" \
            ps --format json 2>/dev/null \
            | grep -o "\"$service\"[^}]*\"Health\":\"[^\"]*\"" \
            | grep -o '"Health":"[^"]*"' \
            | cut -d'"' -f4 || echo "unknown")

        if [ "$status" = "healthy" ]; then
            log_info "${service} is healthy."
            return 0
        fi

        attempt=$((attempt + 1))
        sleep "$interval"
    done

    log_warn "${service} did not become healthy within $((max_attempts * interval))s."
    return 1
}

banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'

  _____ _                    _    ____ _
 |_   _| |__  _ __ ___  __ _| |_ / ___| | __ ___      __
   | | | '_ \| '__/ _ \/ _` | __| |   | |/ _` \ \ /\ / /
   | | | | | | | |  __/ (_| | |_| |___| | (_| |\ V  V /
   |_| |_| |_|_|  \___|\__,_|\__|\____|_|\__,_| \_/\_/

BANNER
    echo -e "  ${BOLD}Autonomous Cybersecurity Agent for SMBs${NC}"
    echo -e "  ${BLUE}Version ${THREATCLAW_VERSION}${NC}"
    echo ""
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --uninstall   Remove ThreatClaw and all associated data
  --update      Pull the latest version and restart services
  --status      Show current ThreatClaw service status
  --no-tls      Skip self-signed TLS certificate generation
  --yes         Skip the initial confirmation prompt
  -h, --help    Show this help message

EOF
}

# ── Parse Arguments ───────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --uninstall) FLAG_UNINSTALL=true ;;
        --update)    FLAG_UPDATE=true ;;
        --status)    FLAG_STATUS=true ;;
        --no-tls)    FLAG_NO_TLS=true ;;
        --yes)       FLAG_YES=true ;;
        -h|--help)   usage; exit 0 ;;
        *)
            log_error "Unknown option: $arg"
            usage
            exit 1
            ;;
    esac
done

# ── Status ────────────────────────────────────────────────────────────────────
if $FLAG_STATUS; then
    banner
    log_step "ThreatClaw Service Status"
    echo ""
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "  Systemd service: ${GREEN}active${NC}"
    else
        echo -e "  Systemd service: ${RED}inactive${NC}"
    fi
    echo ""
    if [ -f "${COMPOSE_DIR}/docker-compose.yml" ]; then
        docker compose -f "${COMPOSE_DIR}/docker-compose.yml" ps 2>/dev/null || true
    else
        log_warn "Docker compose file not found at ${COMPOSE_DIR}/docker-compose.yml"
    fi
    exit 0
fi

# ── Uninstall ─────────────────────────────────────────────────────────────────
if $FLAG_UNINSTALL; then
    banner
    log_step "Uninstalling ThreatClaw..."
    echo ""

    if ! $FLAG_YES; then
        echo -e "${RED}${BOLD}WARNING: This will remove ThreatClaw and ALL its data.${NC}"
        echo -n "Are you sure? [y/N] "
        read -r confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_info "Uninstall cancelled."
            exit 0
        fi
    fi

    # Stop and remove containers
    if [ -f "${COMPOSE_DIR}/docker-compose.yml" ]; then
        log_info "Stopping Docker containers..."
        docker compose -f "${COMPOSE_DIR}/docker-compose.yml" down -v --remove-orphans 2>/dev/null || true
    fi

    # Remove systemd service
    if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
        log_info "Removing systemd service..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
    fi

    # Remove install directory
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Removing ${INSTALL_DIR}..."
        rm -rf "$INSTALL_DIR"
    fi

    # Remove system user
    if id "$SYSTEM_USER" &>/dev/null; then
        log_info "Removing system user '${SYSTEM_USER}'..."
        userdel -r "$SYSTEM_USER" 2>/dev/null || userdel "$SYSTEM_USER" 2>/dev/null || true
    fi

    log_info "ThreatClaw has been uninstalled."
    exit 0
fi

# ── Update ────────────────────────────────────────────────────────────────────
if $FLAG_UPDATE; then
    banner
    log_step "Updating ThreatClaw..."

    if [ ! -d "$INSTALL_DIR" ]; then
        log_error "ThreatClaw is not installed at ${INSTALL_DIR}. Run install first."
        exit 1
    fi

    cd "$INSTALL_DIR"

    log_info "Pulling latest changes from repository..."
    git fetch --all --tags
    git checkout "main"
    git pull origin "main"

    log_info "Pulling latest Docker images..."
    docker compose -f "${COMPOSE_DIR}/docker-compose.yml" pull

    log_info "Rebuilding custom images..."
    docker compose -f "${COMPOSE_DIR}/docker-compose.yml" build

    log_info "Restarting services..."
    docker compose -f "${COMPOSE_DIR}/docker-compose.yml" up -d

    log_info "Update complete."
    docker compose -f "${COMPOSE_DIR}/docker-compose.yml" ps
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# MAIN INSTALLATION
# ══════════════════════════════════════════════════════════════════════════════

banner

# ── Step 1: Initial Confirmation ──────────────────────────────────────────────
if ! $FLAG_YES; then
    echo -e "This will install ThreatClaw ${BOLD}v${THREATCLAW_VERSION}${NC} to ${BOLD}${INSTALL_DIR}${NC}."
    echo ""
    echo -n "Continue? [Y/n] "
    read -r confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled."
        exit 0
    fi
fi

echo ""
mkdir -p "$(dirname "$LOG_FILE")"
echo "--- ThreatClaw install started at $(date -u +"%Y-%m-%dT%H:%M:%SZ") ---" >> "$LOG_FILE"

# ── Step 2: Check Prerequisites ──────────────────────────────────────────────
log_step "Checking prerequisites..."

# Root / sudo
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root or with sudo."
    exit 1
fi

# OS detection
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "$ID" in
        debian)
            if [ "${VERSION_ID:-0}" -lt 12 ]; then
                log_error "Debian 12 (Bookworm) or later is required. Found: ${PRETTY_NAME}"
                exit 1
            fi
            ;;
        ubuntu)
            UBUNTU_MAJOR=$(echo "${VERSION_ID}" | cut -d. -f1)
            if [ "${UBUNTU_MAJOR}" -lt 22 ]; then
                log_error "Ubuntu 22.04 or later is required. Found: ${PRETTY_NAME}"
                exit 1
            fi
            ;;
        *)
            log_warn "Unsupported distribution: ${PRETTY_NAME}. Proceeding anyway (may fail)."
            ;;
    esac
    log_info "OS: ${PRETTY_NAME}"
else
    log_error "Cannot detect OS. /etc/os-release not found."
    exit 1
fi

# Architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|aarch64)
        log_info "Architecture: ${ARCH}"
        ;;
    *)
        log_error "Unsupported architecture: ${ARCH}. Only x86_64 and arm64 are supported."
        exit 1
        ;;
esac

# ── Step 3: Check Minimum Requirements ───────────────────────────────────────
log_step "Checking minimum system requirements..."

# CPU cores
CPU_CORES=$(nproc)
if [ "$CPU_CORES" -lt 2 ]; then
    log_error "Minimum 2 CPU cores required. Found: ${CPU_CORES}"
    exit 1
fi
log_info "CPU cores: ${CPU_CORES}"

# Memory (in kB)
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_GB=$((TOTAL_MEM_KB / 1024 / 1024))
if [ "$TOTAL_MEM_KB" -lt 3800000 ]; then  # ~3.7 GB allows for slight variations
    log_error "Minimum 4 GB RAM required. Found: ~${TOTAL_MEM_GB} GB"
    exit 1
fi
log_info "Memory: ~${TOTAL_MEM_GB} GB"

# Disk space (in kB)
AVAILABLE_DISK_KB=$(df / | tail -1 | awk '{print $4}')
AVAILABLE_DISK_GB=$((AVAILABLE_DISK_KB / 1024 / 1024))
if [ "$AVAILABLE_DISK_KB" -lt 20000000 ]; then  # ~20 GB
    log_error "Minimum 20 GB free disk space required. Found: ~${AVAILABLE_DISK_GB} GB"
    exit 1
fi
log_info "Available disk: ~${AVAILABLE_DISK_GB} GB"

# ── Step 4: Install Docker + Docker Compose ──────────────────────────────────
log_step "Ensuring Docker is installed..."

if check_command docker && docker compose version &>/dev/null; then
    log_info "Docker and Docker Compose are already installed."
    docker --version | tee -a "$LOG_FILE"
    docker compose version | tee -a "$LOG_FILE"
else
    log_info "Installing Docker via official script..."

    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        ca-certificates curl gnupg lsb-release

    if ! check_command docker; then
        curl -fsSL https://get.docker.com | sh
    fi

    systemctl enable docker
    systemctl start docker

    # Verify docker compose (v2 plugin)
    if ! docker compose version &>/dev/null; then
        log_error "Docker Compose plugin not found after Docker install."
        exit 1
    fi

    log_info "Docker installed successfully."
    docker --version | tee -a "$LOG_FILE"
    docker compose version | tee -a "$LOG_FILE"
fi

# ── Step 5: Create System User ───────────────────────────────────────────────
log_step "Creating system user '${SYSTEM_USER}'..."

if id "$SYSTEM_USER" &>/dev/null; then
    log_info "User '${SYSTEM_USER}' already exists."
else
    useradd \
        --system \
        --create-home \
        --home-dir "/home/${SYSTEM_USER}" \
        --shell /usr/sbin/nologin \
        --comment "ThreatClaw service account" \
        "$SYSTEM_USER"
    log_info "User '${SYSTEM_USER}' created."
fi

# Add user to docker group
if ! groups "$SYSTEM_USER" | grep -q '\bdocker\b'; then
    usermod -aG docker "$SYSTEM_USER"
    log_info "Added '${SYSTEM_USER}' to the docker group."
fi

# ── Step 6: Clone / Update Repository ────────────────────────────────────────
log_step "Setting up ThreatClaw at ${INSTALL_DIR}..."

# Ensure git is available
if ! check_command git; then
    log_info "Installing git..."
    apt-get install -y -qq --no-install-recommends git
fi

if [ -d "${INSTALL_DIR}/.git" ]; then
    log_info "Repository already exists. Pulling latest changes..."
    cd "$INSTALL_DIR"
    git fetch --all --tags
    git checkout "main" 2>/dev/null || true
    git pull origin "main" 2>/dev/null || true
else
    log_info "Cloning repository..."
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --depth 1 --branch "main" "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
chown -R "$SYSTEM_USER":"$SYSTEM_USER" "$INSTALL_DIR"

# ── Step 7: Generate .env File ────────────────────────────────────────────────
log_step "Generating environment configuration..."

if [ -f "$ENV_FILE" ]; then
    log_info ".env file already exists. Preserving existing configuration."
else
    TC_DB_PASSWORD=$(generate_password 32)
    TC_INSTANCE_ID=$(generate_password 12)

    cat > "$ENV_FILE" << ENVEOF
# ──────────────────────────────────────────────────────────────────────────────
# ThreatClaw Environment Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Version:   ${THREATCLAW_VERSION}
# ──────────────────────────────────────────────────────────────────────────────

# Database
TC_DB_PASSWORD=${TC_DB_PASSWORD}
DATABASE_URL=postgres://threatclaw:${TC_DB_PASSWORD}@threatclaw-db:5432/threatclaw

# Instance
TC_INSTANCE_ID=${TC_INSTANCE_ID}
TC_PERMISSION_LEVEL=ALERT_ONLY

# Logging
RUST_LOG=threatclaw=info

# Dashboard
NEXT_PUBLIC_API_URL=http://threatclaw-core:18789

# TLS (set to paths of your own certs, or use the generated self-signed certs)
TC_TLS_CERT=/opt/threatclaw/certs/threatclaw.crt
TC_TLS_KEY=/opt/threatclaw/certs/threatclaw.key
ENVEOF

    chmod 600 "$ENV_FILE"
    chown "$SYSTEM_USER":"$SYSTEM_USER" "$ENV_FILE"
    log_info ".env generated with random database password."
fi

# ── Step 8: Generate Self-Signed TLS Certificate ─────────────────────────────
if $FLAG_NO_TLS; then
    log_info "Skipping TLS certificate generation (--no-tls)."
else
    log_step "Generating self-signed TLS certificate..."

    mkdir -p "$CERT_DIR"

    if [ -f "${CERT_DIR}/threatclaw.crt" ] && [ -f "${CERT_DIR}/threatclaw.key" ]; then
        log_info "TLS certificate already exists. Skipping generation."
    else
        if ! check_command openssl; then
            apt-get install -y -qq --no-install-recommends openssl
        fi

        HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname)

        openssl req -x509 -nodes \
            -days 365 \
            -newkey rsa:2048 \
            -keyout "${CERT_DIR}/threatclaw.key" \
            -out "${CERT_DIR}/threatclaw.crt" \
            -subj "/C=US/ST=State/L=City/O=ThreatClaw/CN=${HOSTNAME_FQDN}" \
            -addext "subjectAltName=DNS:${HOSTNAME_FQDN},DNS:localhost,IP:127.0.0.1" \
            2>>"$LOG_FILE"

        chmod 600 "${CERT_DIR}/threatclaw.key"
        chmod 644 "${CERT_DIR}/threatclaw.crt"
        chown -R "$SYSTEM_USER":"$SYSTEM_USER" "$CERT_DIR"

        log_info "Self-signed TLS certificate generated for ${HOSTNAME_FQDN}."
    fi
fi

# ── Step 9: Run Database Migrations ──────────────────────────────────────────
log_step "Running database migrations..."

# Start only the database to run migrations
cd "$COMPOSE_DIR"
docker compose --env-file "$ENV_FILE" -f docker-compose.yml up -d threatclaw-db

# Wait for database to become healthy
MIGRATION_ATTEMPTS=0
while [ $MIGRATION_ATTEMPTS -lt 30 ]; do
    if docker compose --env-file "$ENV_FILE" -f docker-compose.yml \
        exec -T threatclaw-db pg_isready -U threatclaw &>/dev/null; then
        break
    fi
    MIGRATION_ATTEMPTS=$((MIGRATION_ATTEMPTS + 1))
    sleep 2
done

if [ $MIGRATION_ATTEMPTS -ge 30 ]; then
    log_error "Database did not become ready in time."
    exit 1
fi

log_info "Database is ready. Migrations will run on first core startup."

# ── Step 10: Pull Docker Images ──────────────────────────────────────────────
log_step "Pulling Docker images..."

cd "$COMPOSE_DIR"
docker compose --env-file "$ENV_FILE" -f docker-compose.yml pull --ignore-pull-failures 2>&1 | tee -a "$LOG_FILE"

log_info "Building custom images (core, dashboard)..."
docker compose --env-file "$ENV_FILE" -f docker-compose.yml build 2>&1 | tee -a "$LOG_FILE"

# ── Step 11: Start the Stack ─────────────────────────────────────────────────
log_step "Starting ThreatClaw stack..."

cd "$COMPOSE_DIR"
docker compose --env-file "$ENV_FILE" -f docker-compose.yml up -d 2>&1 | tee -a "$LOG_FILE"

# ── Step 12: Install Systemd Service ─────────────────────────────────────────
log_step "Installing systemd service..."

INSTALLER_DIR="${INSTALL_DIR}/installer"
SERVICE_SRC="${INSTALLER_DIR}/threatclaw.service"
SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}.service"

if [ -f "$SERVICE_SRC" ]; then
    cp "$SERVICE_SRC" "$SERVICE_DST"
else
    cat > "$SERVICE_DST" << 'SERVICEEOF'
[Unit]
Description=ThreatClaw Cybersecurity Agent
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/threatclaw/docker
ExecStart=/usr/bin/docker compose --env-file /opt/threatclaw/.env up -d
ExecStop=/usr/bin/docker compose --env-file /opt/threatclaw/.env down
TimeoutStartSec=300
User=root

[Install]
WantedBy=multi-user.target
SERVICEEOF
fi

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" 2>/dev/null
log_info "Systemd service installed and enabled."

# ── Step 13: Wait for Health Checks ──────────────────────────────────────────
log_step "Waiting for services to become healthy..."

# Give containers a moment to start
sleep 5

wait_for_healthy "threatclaw-db" 30 2 || true
wait_for_healthy "threatclaw-core" 60 3 || true

# ── Step 14: Print Summary ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}  ThreatClaw v${THREATCLAW_VERSION} installed successfully!${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo ""
echo -e "  ${BOLD}Install directory:${NC}  ${INSTALL_DIR}"
echo -e "  ${BOLD}Compose file:${NC}      ${COMPOSE_DIR}/docker-compose.yml"
echo -e "  ${BOLD}Environment:${NC}       ${ENV_FILE}"
echo ""
echo -e "  ${BOLD}Service URLs:${NC}"
echo -e "    Dashboard:       ${CYAN}https://$(hostname -f 2>/dev/null || hostname)${NC}"
echo -e "    Dashboard (alt): ${CYAN}http://localhost:3000${NC}"
echo -e "    API:             ${CYAN}http://localhost:18789${NC}"
echo ""
echo -e "  ${BOLD}Management:${NC}"
echo -e "    Status:          ${BLUE}sudo systemctl status ${SERVICE_NAME}${NC}"
echo -e "    Logs:            ${BLUE}sudo docker compose -f ${COMPOSE_DIR}/docker-compose.yml logs -f${NC}"
echo -e "    Stop:            ${BLUE}sudo systemctl stop ${SERVICE_NAME}${NC}"
echo -e "    Start:           ${BLUE}sudo systemctl start ${SERVICE_NAME}${NC}"
echo -e "    Update:          ${BLUE}sudo ${INSTALL_DIR}/installer/install.sh --update${NC}"
echo -e "    Uninstall:       ${BLUE}sudo ${INSTALL_DIR}/installer/install.sh --uninstall${NC}"
echo ""
echo -e "  ${BOLD}Container status:${NC}"
docker compose -f "${COMPOSE_DIR}/docker-compose.yml" ps 2>/dev/null || true
echo ""
echo -e "  ${YELLOW}Note: If using self-signed TLS, your browser will show a security warning.${NC}"
echo -e "  ${YELLOW}Replace certs in ${CERT_DIR}/ with your own for production use.${NC}"
echo ""
echo -e "  ${BOLD}Install log:${NC} ${LOG_FILE}"
echo ""

echo "--- ThreatClaw install completed at $(date -u +"%Y-%m-%dT%H:%M:%SZ") ---" >> "$LOG_FILE"
