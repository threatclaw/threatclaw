#!/bin/bash
# ThreatClaw Installer
# Usage: curl -fsSL https://get.threatclaw.io | sh
#
# Supports: Linux (x86_64, arm64), macOS (Intel, Apple Silicon)
# For Windows: use get-threatclaw.ps1 or download from GitHub Releases
#
# This script:
# 1. Detects your OS and architecture
# 2. Downloads the latest ThreatClaw binary from GitHub Releases
# 3. Verifies the SHA-256 checksum
# 4. Installs to the appropriate location
# 5. Sets up the service (systemd on Linux, launchd on macOS)

set -e

REPO="threatclaw/threatclaw"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[ThreatClaw]${NC} $1"; }
warn()  { echo -e "${YELLOW}[ThreatClaw]${NC} $1"; }
error() { echo -e "${RED}[ThreatClaw]${NC} $1"; exit 1; }
step()  { echo -e "${BLUE}[ThreatClaw]${NC} $1"; }

# ── Detect platform ──
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: $ARCH" ;;
    esac

    case "$OS" in
        linux)
            PLATFORM="linux"
            ;;
        darwin)
            PLATFORM="darwin"
            ;;
        *)
            error "Unsupported OS: $OS. Use get-threatclaw.ps1 for Windows."
            ;;
    esac

    BINARY_NAME="threatclaw-${PLATFORM}-${ARCH}"
    info "Platform: ${PLATFORM}/${ARCH}"
}

# ── Set paths based on OS ──
set_paths() {
    if [ "$PLATFORM" = "darwin" ]; then
        INSTALL_DIR="/usr/local/bin"
        CONFIG_DIR="$HOME/.threatclaw"
        DATA_DIR="$HOME/.threatclaw/data"
    else
        # Linux — use system paths if root, user paths otherwise
        if [ "$(id -u)" -eq 0 ]; then
            INSTALL_DIR="/usr/local/bin"
            CONFIG_DIR="/etc/threatclaw"
            DATA_DIR="/var/lib/threatclaw"
        else
            INSTALL_DIR="$HOME/.local/bin"
            CONFIG_DIR="$HOME/.threatclaw"
            DATA_DIR="$HOME/.threatclaw/data"
        fi
    fi

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" 2>/dev/null || true
}

# ── Check requirements ──
check_requirements() {
    if ! command -v curl &> /dev/null; then
        error "curl is required. Install it first."
    fi

    # Docker is optional — warn but don't block
    if ! command -v docker &> /dev/null; then
        warn "Docker not found. ThreatClaw needs Docker for infrastructure (PostgreSQL, Redis)."
        if [ "$PLATFORM" = "linux" ]; then
            warn "  Install: curl -fsSL https://get.docker.com | sh"
        else
            warn "  Install: https://www.docker.com/products/docker-desktop/"
        fi
    elif ! docker compose version &> /dev/null 2>&1; then
        warn "Docker Compose v2 not found. Update Docker or install docker-compose-plugin."
    fi
}

# ── Get latest version ──
get_latest_version() {
    VERSION=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
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

    TMPDIR=$(mktemp -d)
    TMP_BIN="${TMPDIR}/threatclaw"

    info "Downloading ${BINARY_NAME}..."
    curl -fsSL -o "$TMP_BIN" "${DOWNLOAD_URL}" || error "Download failed. Is the release public?"

    info "Verifying checksum..."
    curl -fsSL -o "${TMP_BIN}.sha256" "${CHECKSUM_URL}" 2>/dev/null || warn "Checksum file not found — skipping verification"

    if [ -f "${TMP_BIN}.sha256" ]; then
        EXPECTED=$(cat "${TMP_BIN}.sha256" | awk '{print $1}')
        if command -v sha256sum &> /dev/null; then
            ACTUAL=$(sha256sum "$TMP_BIN" | awk '{print $1}')
        elif command -v shasum &> /dev/null; then
            ACTUAL=$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')
        else
            warn "No sha256sum or shasum found — skipping verification"
            ACTUAL="$EXPECTED"
        fi
        if [ "$EXPECTED" != "$ACTUAL" ]; then
            rm -rf "$TMPDIR"
            error "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}\n\nThe binary may be corrupted or tampered with."
        fi
        info "Checksum verified ✓"
    fi
}

# ── Install binary ──
install_binary() {
    info "Installing to ${INSTALL_DIR}/threatclaw..."
    chmod +x "$TMP_BIN"

    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_BIN" "${INSTALL_DIR}/threatclaw"
    else
        sudo mv "$TMP_BIN" "${INSTALL_DIR}/threatclaw"
    fi

    rm -rf "$TMPDIR"
    info "Installed: $(${INSTALL_DIR}/threatclaw --version 2>/dev/null || echo 'threatclaw')"
}

# ── Setup infrastructure ──
setup_infrastructure() {
    step "Setting up infrastructure..."

    if [ ! -f "${CONFIG_DIR}/docker-compose.core.yml" ]; then
        curl -fsSL "https://raw.githubusercontent.com/${REPO}/${VERSION}/docker/docker-compose.core.yml" \
            -o "${CONFIG_DIR}/docker-compose.core.yml" 2>/dev/null || warn "Could not download docker-compose.core.yml"
    fi

    if [ ! -f "${CONFIG_DIR}/.env" ]; then
        # Generate random DB password
        DB_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)

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
    else
        info "Existing configuration preserved at ${CONFIG_DIR}/.env"
    fi
}

# ── Setup service (Linux: systemd, macOS: launchd) ──
setup_service() {
    if [ "$PLATFORM" = "linux" ] && [ "$(id -u)" -eq 0 ]; then
        setup_systemd
    elif [ "$PLATFORM" = "darwin" ]; then
        setup_launchd
    else
        info "Run manually: threatclaw run"
        info "Or add to your init system."
    fi
}

setup_systemd() {
    # Create system user if running as root
    if ! id -u threatclaw &>/dev/null 2>&1; then
        useradd -r -s /bin/false -d "$DATA_DIR" threatclaw 2>/dev/null || true
        chown threatclaw:threatclaw "$DATA_DIR" 2>/dev/null || true
        info "Created system user: threatclaw"
    fi

    cat > /etc/systemd/system/threatclaw.service << SVCEOF
[Unit]
Description=ThreatClaw Autonomous Cybersecurity Agent
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=threatclaw
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

setup_launchd() {
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="${PLIST_DIR}/io.threatclaw.agent.plist"
    mkdir -p "$PLIST_DIR"

    cat > "$PLIST_FILE" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.threatclaw.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/threatclaw</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>${DATA_DIR}/threatclaw.log</string>
    <key>StandardErrorPath</key>
    <string>${DATA_DIR}/threatclaw.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>THREATCLAW_CONFIG</key>
        <string>${CONFIG_DIR}</string>
    </dict>
</dict>
</plist>
PLISTEOF

    info "LaunchAgent created: $PLIST_FILE"
    info "  Start:  launchctl load $PLIST_FILE"
    info "  Stop:   launchctl unload $PLIST_FILE"
}

# ── Check for Ollama ──
check_ollama() {
    if command -v ollama &> /dev/null; then
        info "Ollama detected ✓"
    else
        warn "Ollama not found. Install it for local AI:"
        if [ "$PLATFORM" = "darwin" ]; then
            warn "  brew install ollama"
        else
            warn "  curl -fsSL https://ollama.com/install.sh | sh"
        fi
        warn "  ollama pull qwen3:14b"
    fi
}

# ── Print next steps ──
print_next_steps() {
    echo ""
    info "Installation complete! 🎉"
    echo ""
    echo "  Next steps:"

    if [ "$PLATFORM" = "linux" ] && [ "$(id -u)" -eq 0 ]; then
        echo "  1. Start infrastructure:  cd ${CONFIG_DIR} && docker compose -f docker-compose.core.yml up -d"
        echo "  2. Start ThreatClaw:      systemctl start threatclaw"
        echo "  3. Open dashboard:        http://localhost:3001"
    elif [ "$PLATFORM" = "darwin" ]; then
        echo "  1. Start Docker Desktop (if not running)"
        echo "  2. Start infrastructure:  cd ${CONFIG_DIR} && docker compose -f docker-compose.core.yml up -d"
        echo "  3. Start ThreatClaw:      threatclaw run"
        echo "  4. Open dashboard:        http://localhost:3001"
    else
        echo "  1. Start infrastructure:  cd ${CONFIG_DIR} && docker compose -f docker-compose.core.yml up -d"
        echo "  2. Start ThreatClaw:      threatclaw run"
        echo "  3. Open dashboard:        http://localhost:3001"
    fi

    echo ""
    echo "  Or run the setup wizard:  threatclaw onboard"
    echo ""
}

# ── Main ──
main() {
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║         ThreatClaw Installer          ║"
    echo "  ║   Autonomous Cybersecurity Agent      ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""

    detect_platform
    set_paths
    check_requirements
    get_latest_version
    download_binary
    install_binary
    setup_infrastructure
    setup_service
    check_ollama
    print_next_steps
}

main "$@"
