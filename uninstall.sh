#!/bin/bash
# ============================================================
# PacketSentinel — Uninstaller
# Usage: sudo bash uninstall.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[PacketSentinel]${RESET} $1"; }
success() { echo -e "${GREEN}[✓]${RESET} $1"; }
warning() { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${RESET}"; }

# ── Root check ───────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo bash uninstall.sh"
fi

echo ""
echo -e "${RED}${BOLD}  PacketSentinel — Uninstaller${RESET}"
echo ""
warning "This will stop and remove PacketSentinel from your system."
read -p "$(echo -e ${YELLOW}[!]${RESET}) Are you sure? [y/N]: " CONFIRM
CONFIRM=${CONFIRM:-N}

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    info "Uninstall cancelled."
    exit 0
fi

# ── Step 1 — Stop service ────────────────────────────────────
section "Step 1 — Stopping Service"
if systemctl is-active --quiet packetsentinel; then
    systemctl stop packetsentinel
    success "Service stopped"
else
    info "Service was not running"
fi

# ── Step 2 — Disable service ─────────────────────────────────
section "Step 2 — Disabling Service"
if systemctl is-enabled --quiet packetsentinel 2>/dev/null; then
    systemctl disable packetsentinel
    success "Service disabled"
else
    info "Service was not enabled"
fi

# ── Step 3 — Remove service file ─────────────────────────────
section "Step 3 — Removing Systemd Service"
SERVICE_FILE="/etc/systemd/system/packetsentinel.service"
if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    success "Service file removed"
else
    info "Service file not found — skipping"
fi

# ── Step 4 — Ask about data ──────────────────────────────────
section "Step 4 — Removing Data"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

read -p "$(echo -e ${YELLOW}[!]${RESET}) Delete alerts database and logs? [y/N]: " DEL_DATA
DEL_DATA=${DEL_DATA:-N}

if [[ "$DEL_DATA" =~ ^[Yy]$ ]]; then
    rm -f "$INSTALL_DIR/data/alerts.db"
    rm -f "$INSTALL_DIR/packetsentinel.log"
    success "Database and logs removed"
else
    info "Keeping database and logs"
fi

# ── Step 5 — Remove virtual environment ──────────────────────
section "Step 5 — Removing Virtual Environment"
read -p "$(echo -e ${YELLOW}[!]${RESET}) Remove Python virtual environment? [y/N]: " DEL_VENV
DEL_VENV=${DEL_VENV:-N}

if [[ "$DEL_VENV" =~ ^[Yy]$ ]]; then
    rm -rf "$INSTALL_DIR/venv"
    success "Virtual environment removed"
else
    info "Keeping virtual environment"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   PacketSentinel Uninstalled Successfully ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""
info "Project files are still at: $INSTALL_DIR"
info "You can safely delete the folder manually if needed."
echo ""