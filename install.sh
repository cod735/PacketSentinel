#!/bin/bash
# ============================================================
# PacketSentinel — Auto Installer
# Supports: Ubuntu 20.04, 22.04, 24.04 / Debian 11, 12
# Usage: sudo bash install.sh
# By Abbas Khan | github.com/cod735
# ============================================================

set -e  # Exit immediately if any command fails

# ── Colors ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helper functions ─────────────────────────────────────────
info()    { echo -e "${CYAN}[PacketSentinel]${RESET} $1"; }
success() { echo -e "${GREEN}[✓]${RESET} $1"; }
warning() { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${RESET}"; }

# ── Banner ───────────────────────────────────────────────────
echo -e "${CYAN}"
echo '██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗'
echo '██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝'
echo '██████╔╝███████║██║     █████╔╝ █████╗     ██║   '
echo '██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   '
echo '██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   '
echo '╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   '
echo -e "${RESET}"
echo -e "${BOLD}  PacketSentinel — Network Traffic Monitor${RESET}"
echo -e "${CYAN}  By Abbas Khan | github.com/cod735${RESET}"
echo ""

# ════════════════════════════════════════════════════════════
# STEP 1 — Root check
# ════════════════════════════════════════════════════════════
section "Step 1 — Checking Permissions"
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo bash install.sh"
fi
success "Running as root"

# ════════════════════════════════════════════════════════════
# STEP 2 — OS check
# ════════════════════════════════════════════════════════════
section "Step 2 — Checking Operating System"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
    info "Detected: $PRETTY_NAME"
    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        warning "PacketSentinel is tested on Ubuntu/Debian."
        warning "Other distros may work but are not officially supported."
    else
        success "OS supported: $PRETTY_NAME"
    fi
else
    warning "Could not detect OS — proceeding anyway."
fi

# ════════════════════════════════════════════════════════════
# STEP 3 — Install system dependencies
# ════════════════════════════════════════════════════════════
section "Step 3 — Installing System Dependencies"
info "Updating package lists..."
apt-get update -qq

info "Installing python3, pip, wget, libpcap..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    wget \
    libpcap-dev \
    net-tools

success "System dependencies installed"

# ════════════════════════════════════════════════════════════
# STEP 4 — Set up project directory
# ════════════════════════════════════════════════════════════
section "Step 4 — Setting Up Project"

# Get the directory where install.sh lives
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Installing from: $INSTALL_DIR"

# Create data directory if missing
mkdir -p "$INSTALL_DIR/data"

# Create virtual environment
info "Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
success "Virtual environment created"

# ════════════════════════════════════════════════════════════
# STEP 5 — Install Python libraries
# ════════════════════════════════════════════════════════════
section "Step 5 — Installing Python Libraries"
info "Installing flask, scapy, geoip2, requests, netifaces..."
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet \
    flask \
    scapy \
    geoip2 \
    requests \
    netifaces

success "Python libraries installed"

# ════════════════════════════════════════════════════════════
# STEP 6 — Download GeoIP database
# ════════════════════════════════════════════════════════════
section "Step 6 — Downloading GeoIP Database"
GEOIP_PATH="$INSTALL_DIR/data/GeoLite2-Country.mmdb"

if [ -f "$GEOIP_PATH" ]; then
    success "GeoIP database already exists — skipping download"
else
    info "Downloading MaxMind GeoLite2 database..."
    wget -q -O "$GEOIP_PATH" \
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

    if [ -f "$GEOIP_PATH" ]; then
        success "GeoIP database downloaded"
    else
        warning "GeoIP download failed — country lookup will be unavailable"
        warning "You can download it manually from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    fi
fi

# ════════════════════════════════════════════════════════════
# STEP 7 — Create blocklist if missing
# ════════════════════════════════════════════════════════════
section "Step 7 — Setting Up Blocklist"
BLOCKLIST_PATH="$INSTALL_DIR/data/blocklist.txt"

if [ -f "$BLOCKLIST_PATH" ]; then
    success "Blocklist already exists"
else
    info "Creating default blocklist..."
    cat > "$BLOCKLIST_PATH" << 'EOF'
# PacketSentinel Blocklist
# Add one IP per line
# Lines starting with # are ignored
# Known Tor exit nodes
185.220.101.1
185.220.101.2
185.220.101.3
185.220.102.8
185.220.103.7
# Known scanners
45.33.32.156
89.248.167.131
EOF
    success "Default blocklist created"
fi

# ════════════════════════════════════════════════════════════
# STEP 8 — Create systemd service
# ════════════════════════════════════════════════════════════
section "Step 8 — Creating Systemd Service"

SERVICE_FILE="/etc/systemd/system/packetsentinel.service"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=PacketSentinel — Network Traffic Monitor
Documentation=https://github.com/cod735/packetsentinel
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/main.py
Restart=on-failure
RestartSec=5s
StandardOutput=append:$INSTALL_DIR/packetsentinel.log
StandardError=append:$INSTALL_DIR/packetsentinel.log

[Install]
WantedBy=multi-user.target
EOF

success "Systemd service created at $SERVICE_FILE"

# ════════════════════════════════════════════════════════════
# STEP 9 — Enable and start service
# ════════════════════════════════════════════════════════════
section "Step 9 — Enabling Service"

systemctl daemon-reload
systemctl enable packetsentinel
success "Service enabled — will start on boot"

# Ask user if they want to start now
echo ""
read -p "$(echo -e ${CYAN}[PacketSentinel]${RESET}) Start PacketSentinel now? [Y/n]: " START_NOW
START_NOW=${START_NOW:-Y}

if [[ "$START_NOW" =~ ^[Yy]$ ]]; then
    systemctl start packetsentinel
    sleep 2
    if systemctl is-active --quiet packetsentinel; then
        success "PacketSentinel is running!"
    else
        warning "Service may have failed to start."
        warning "Check logs: journalctl -u packetsentinel -n 20"
    fi
fi

# ════════════════════════════════════════════════════════════
# DONE
# ════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   PacketSentinel Installed Successfully! ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}Dashboard :${RESET} http://localhost:5001"
echo -e "  ${CYAN}Logs      :${RESET} $INSTALL_DIR/packetsentinel.log"
echo -e "  ${CYAN}Status    :${RESET} systemctl status packetsentinel"
echo -e "  ${CYAN}Stop      :${RESET} systemctl stop packetsentinel"
echo -e "  ${CYAN}Restart   :${RESET} systemctl restart packetsentinel"
echo ""
echo -e "  ${YELLOW}GitHub    :${RESET} github.com/cod735"
echo ""