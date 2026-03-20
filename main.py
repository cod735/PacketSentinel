# main.py
# PacketSentinel — Main Entry Point
# Run with: sudo python3 main.py

import os
import sys
import time
import signal
import logging

from config import (
    INTERFACE,
    FLASK_HOST,
    FLASK_PORT,
    FLASK_DEBUG,
    LOG_FILE,
    LOG_LEVEL,
)


# ════════════════════════════════════════════════════════════
# LOGGING SETUP
# ════════════════════════════════════════════════════════════
def setup_logging():
    """
    Sets up logging to both terminal and log file.
    """
    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )


# ════════════════════════════════════════════════════════════
# STARTUP CHECKS
# ════════════════════════════════════════════════════════════
def check_root():
    """PacketSentinel needs root to capture raw packets."""
    if os.geteuid() != 0:
        print("❌ PacketSentinel must be run as root.")
        print("   Use: sudo python3 main.py")
        sys.exit(1)


def check_interface():
    """
    Checks if the auto-detected interface exists.
    If not, auto-switches to first available real interface.
    Works on any Linux machine.
    """
    interfaces = os.listdir("/sys/class/net/")
    if INTERFACE not in interfaces:
        print(f"⚠️  Interface '{INTERFACE}' not found.")
        real = [i for i in interfaces if i != "lo"]
        if real:
            import config
            config.INTERFACE = real[0]
            print(f"✅ Auto-switched to available interface: {config.INTERFACE}")
        else:
            print("❌ No usable network interface found. Exiting.")
            sys.exit(1)
    else:
        print(f"✅ Interface detected: {INTERFACE}")


def check_geoip_database():
    """Warn if GeoIP database is missing — tool still works without it."""
    from config import GEOIP_DB_PATH
    if not os.path.exists(GEOIP_DB_PATH):
        print(f"⚠️  GeoIP database not found at {GEOIP_DB_PATH}")
        print("   Country lookup will be unavailable.")
        print("   See README.md for download instructions.")
    else:
        print("✅ GeoIP database found.")


# ════════════════════════════════════════════════════════════
# BANNER
# ════════════════════════════════════════════════════════════
def print_banner():
    banner = """
\033[96m
██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
██████╔╝███████║██║     █████╔╝ █████╗     ██║
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝

███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
\033[0m
\033[92m  Network Traffic Monitor & Anomaly Detector\033[0m
\033[90m  By Abbas Khan | github.com/cod735\033[0m
    """
    print(banner)
    print(f"\033[93m  Interface  : {INTERFACE}\033[0m")
    print(f"\033[93m  Dashboard  : http://localhost:{FLASK_PORT}\033[0m")
    print(f"\033[93m  Log file   : {LOG_FILE}\033[0m")
    print()


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════
def main():
    # ── Step 1: Startup checks ───────────────────────────────
    check_root()
    check_interface()
    check_geoip_database()
    setup_logging()
    print_banner()

    # ── Step 2: Import engines after checks pass ─────────────
    from core.sniffer import PacketSniffer
    from dashboard.app import create_app

    # ── Step 3: Start the sniffer ────────────────────────────
    sniffer = PacketSniffer()
    sniffer.start()

    # ── Step 4: Create Flask app ─────────────────────────────
    app = create_app(sniffer)

    # ── Step 5: Handle Ctrl+C clean shutdown ─────────────────
    def shutdown(signum, frame):
        print("\n\n[PacketSentinel] 🛑 Shutting down...")
        sniffer.stop()
        sniffer.geoip.close()
        print("[PacketSentinel] 💾 All data saved to database.")
        print("[PacketSentinel] 👋 Goodbye!\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Step 6: Start Flask ───────────────────────────────────
    print(f"[PacketSentinel] 🌐 Dashboard at http://localhost:{FLASK_PORT}")
    print(f"[PacketSentinel] 🔴 Press Ctrl+C to stop\n")

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=FLASK_DEBUG,
        use_reloader=False
    )


# ════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    main()