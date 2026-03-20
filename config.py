# config.py
# PacketSentinel — Central Configuration File
# All settings live here. Never hardcode values inside other files.

import os
import netifaces


# ─────────────────────────────────────────
# AUTO-DETECT NETWORK INTERFACE
# ─────────────────────────────────────────
def _get_default_interface():
    """
    Auto-detects the default network interface.
    Works on any Linux machine — no hardcoding needed.
    Falls back to first available interface, then 'eth0'.
    """
    try:
        # Method 1: Get interface used for default gateway
        gws = netifaces.gateways()
        default = gws.get("default", {})
        if netifaces.AF_INET in default:
            return default[netifaces.AF_INET][1]
    except Exception:
        pass

    try:
        # Method 2: Pick first real interface (skip loopback)
        all_interfaces = os.listdir("/sys/class/net/")
        real = [i for i in all_interfaces if i != "lo"]
        if real:
            return real[0]
    except Exception:
        pass

    # Method 3: Final fallback
    return "eth0"


# ─────────────────────────────────────────
# PROJECT PATHS
# ─────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DATA_DIR       = os.path.join(BASE_DIR, "data")
DB_PATH        = os.path.join(DATA_DIR, "alerts.db")
BLOCKLIST_PATH = os.path.join(DATA_DIR, "blocklist.txt")
GEOIP_DB_PATH  = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")

# ─────────────────────────────────────────
# NETWORK SETTINGS
# ─────────────────────────────────────────
# Auto-detected — works on any Linux machine
INTERFACE = _get_default_interface()

# ─────────────────────────────────────────
# BASELINE LEARNING
# ─────────────────────────────────────────
BASELINE_DURATION          = 180   # seconds (2 minutes)
BANDWIDTH_SPIKE_MULTIPLIER = 6.0 # 2x normal = alert

# ─────────────────────────────────────────
# PORT SCAN DETECTION
# ─────────────────────────────────────────
PORT_SCAN_THRESHOLD = 15   # unique ports
PORT_SCAN_WINDOW    = 10   # seconds

# ─────────────────────────────────────────
# PROTOCOL ANOMALY
# ─────────────────────────────────────────
EXPECTED_PROTOCOLS = {
    80:   "HTTP",
    443:  "HTTPS",
    22:   "SSH",
    21:   "FTP",
    25:   "SMTP",
    53:   "DNS",
    3306: "MySQL",
    5432: "PostgreSQL",
}

# ─────────────────────────────────────────
# ALERT SEVERITY LEVELS
# ─────────────────────────────────────────
SEVERITY_LOW      = "LOW"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_HIGH     = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# ─────────────────────────────────────────
# FLASK DASHBOARD
# ─────────────────────────────────────────
FLASK_HOST  = "0.0.0.0"
FLASK_PORT  = 5001
FLASK_DEBUG = False

# ─────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────
LOG_FILE  = os.path.join(BASE_DIR, "packetsentinel.log")
LOG_LEVEL = "INFO"