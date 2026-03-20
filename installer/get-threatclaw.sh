#!/bin/bash
# ThreatClaw Installer
# Usage: curl -fsSL https://get.threatclaw.io | sh
#
# This script:
# 1. Detects your OS and architecture
# 2. Downloads the latest ThreatClaw binary from GitHub Releases
# 3. Verifies the SHA-256 checksum
# 4. Installs to /usr/local/bin/
# 5. Creates a systemd service
# 6. Starts the infrastructure (PostgreSQL, Redis, Fluent Bit)

set -e

REPO="threatclaw/threatclaw"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/threatclaw"
DATA_DIR="/var/lib/threatclaw"
SERVICE_USER="threatclaw"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[ThreatClaw]${NC} $1"; }
warn()  { echo -e "${YELLOW}[ThreatClaw]${NC} $1"; }
error() { echo -e "${RED}[ThreatClaw]${NC} $1"; exit 1; }

# ── Check requirements ──
check_requirements() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (sudo)"
    fi

    if ! command -v curl &> /dev/null; then
        error "curl is required. Install it with: apt install curl"
    fi

    if ! command -v docker &> /dev/null; then
        warn "Docker not found. Installing..."
        curl -fsSL https://get.docker.com | sh
    fi

    if ! docker compose version &> /dev/null; then
        error "Docker Compose v2 is required. Update Docker."
    fi
}

# ── Detect platform ──
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)       error "Unsupported architecture: $ARCH" ;;
    esac

    if [ "$OS" != "linux" ]; then
        error "ThreatClaw only supports Linux. Got: $OS"
    fi

    BINARY_NAME="threatclaw-${OS}-${ARCH}"
    info "Platform: ${OS}/${ARCH}"
}

# ── Get latest version ──
get_latest_version() {
    VERSION=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        # Fallback to latest prerelease
        VERSION=$(curl -s "https://api.github.com/repos/${REPO}/releases" | grep '"tag_name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    fi
    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Check https://github.com/${REPO}/releases"
    fi
    info "Version: ${VERSION}"
}

# ── Download and verify ──
download_binary() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}.sha256"

    info "Downloading ${BINARY_NAME}..."
    curl -fsSL -o /tmp/threatclaw "${DOWNLOAD_URL}" || error "Download failed. Is the release public?"

    info "Verifying checksum..."
    curl -fsSL -o /tmp/threatclaw.sha256 "${CHECKSUM_URL}" || warn "Checksum file not found — skipping verification"

    if [ -f /tmp/threatclaw.sha256 ]; then
        EXPECTED=$(cat /tmp/threatclaw.sha256 | awk '{print $1}')
        ACTUAL=$(sha256sum /tmp/threatclaw | awk '{print $1}')
        if [ "$EXPECTED" != "$ACTUAL" ]; then
            error "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}\n\nThe binary may be corrupted or tampered with."
        fi
        info "Checksum verified ✓"
    fi
}

# ── Install ──
install_binary() {
    info "Installing to ${INSTALL_DIR}/threatclaw..."
    chmod +x /tmp/threatclaw
    mv /tmp/threatclaw "${INSTALL_DIR}/threatclaw"

    # Create system user
    if ! id -u "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$DATA_DIR" "$SERVICE_USER"
        info "Created system user: ${SERVICE_USER}"
    fi

    # Create directories
    mkdir -p "$CONFIG_DIR" "$DATA_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"

    info "Installed: $(threatclaw --version 2>/dev/null || echo 'threatclaw')"
}

# ── Setup infrastructure ──
setup_infrastructure() {
    info "Setting up infrastructure..."

    # Clone docker-compose if not present
    if [ ! -f "${CONFIG_DIR}/docker-compose.core.yml" ]; then
        curl -fsSL "https://raw.githubusercontent.com/${REPO}/${VERSION}/docker/docker-compose.core.yml" \
            -o "${CONFIG_DIR}/docker-compose.core.yml" 2>/dev/null || warn "Could not download docker-compose.core.yml"
    fi

    # Generate random DB password
    DB_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)

    # Create .env
    cat > "${CONFIG_DIR}/.env" << ENVEOF
DATABASE_URL=postgres://threatclaw:${DB_PASSWORD}@127.0.0.1:5432/threatclaw
REDIS_URL=redis://127.0.0.1:6379/0
LLM_BACKEND=ollama
TC_PERMISSION_LEVEL=ALERT_ONLY
TC_INSTANCE_NAME=threatclaw
RUST_LOG=info
TC_DB_PASSWORD=${DB_PASSWORD}
ENVEOF
    chmod 600 "${CONFIG_DIR}/.env"

    info "Configuration written to ${CONFIG_DIR}/.env"
}

# ── Create systemd service ──
setup_service() {
    cat > /etc/systemd/system/threatclaw.service << SVCEOF
[Unit]
Description=ThreatClaw Autonomous Cybersecurity Agent
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=${SERVICE_USER}
EnvironmentFile=${CONFIG_DIR}/.env
ExecStart=${INSTALL_DIR}/threatclaw run
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    info "Systemd service created"
}

# ── Check for Ollama ──
check_ollama() {
    if command -v ollama &> /dev/null; then
        info "Ollama detected ✓"
    else
        warn "Ollama not found. Install it for local AI:"
        warn "  curl -fsSL https://ollama.com/install.sh | sh"
        warn "  ollama pull qwen3:14b"
    fi
}

# ── Main ──
main() {
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║         ThreatClaw Installer          ║"
    echo "  ║   Autonomous Cybersecurity Agent      ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""

    check_requirements
    detect_platform
    get_latest_version
    download_binary
    install_binary
    setup_infrastructure
    setup_service
    check_ollama

    echo ""
    info "Installation complete! 🎉"
    echo ""
    echo "  Next steps:"
    echo "  1. Start infrastructure:  cd ${CONFIG_DIR} && docker compose -f docker-compose.core.yml up -d"
    echo "  2. Start ThreatClaw:      systemctl start threatclaw"
    echo "  3. Open dashboard:        http://localhost:3001"
    echo ""
    echo "  Or run manually:          threatclaw run"
    echo ""
}

main "$@"
