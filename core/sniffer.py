# core/sniffer.py
# PacketSentinel — Live Packet Capture Engine
# Captures live packets from the network interface
# and feeds them into the baseline + detection engine.

import threading
import time
from scapy.all import sniff, IP, TCP, UDP, conf
from config import INTERFACE
from core.baseline import BaselineEngine
from core.detector import DetectionEngine
from core.geoip import GeoIPEngine


class PacketSniffer:
    """
    Captures live packets from the network interface.
    Feeds each packet to:
      1. BaselineEngine  — during learning phase
      2. DetectionEngine — after baseline is locked
    """

    def __init__(self):
        # Initialize all engines
        self.geoip    = GeoIPEngine()
        self.baseline = BaselineEngine()
        self.detector = DetectionEngine(self.baseline, self.geoip)

        # ── State ────────────────────────────────────────────────
        self.is_running    = False
        self._sniff_thread = None

        # ── Traffic stats (shown on dashboard) ──────────────────
        self.stats = {
            "total_packets"   : 0,
            "total_alerts"    : 0,
            "packets_per_sec" : 0,
            "start_time"      : time.strftime("%Y-%m-%d %H:%M:%S"),
            "interface"       : INTERFACE, 
        }
        self._pps_counter  = 0
        self._last_pps_tick = time.time()

        # Suppress scapy's verbose output
        conf.verb = 0

        print(f"[PacketSentinel] 📡 Sniffer initialized on interface: {INTERFACE}")

    # ────────────────────────────────────────────────────────────
    # PUBLIC — Start sniffing in background thread
    # ────────────────────────────────────────────────────────────
    def start(self):
        """Starts packet capture in a background thread."""
        if self.is_running:
            print("[PacketSentinel] ⚠️  Sniffer already running.")
            return

        self.is_running    = True
        self._sniff_thread = threading.Thread(
            target=self._run_sniffer,
            daemon=True
        )
        self._sniff_thread.start()
        print(f"[PacketSentinel] ✅ Packet capture started on {INTERFACE}")

    # ────────────────────────────────────────────────────────────
    # PUBLIC — Stop sniffing
    # ────────────────────────────────────────────────────────────
    def stop(self):
        """Stops packet capture."""
        self.is_running = False
        print("[PacketSentinel] 🛑 Packet capture stopped.")

    # ────────────────────────────────────────────────────────────
    # PRIVATE — The actual scapy sniff loop
    # ────────────────────────────────────────────────────────────
    def _run_sniffer(self):
        """
        Runs scapy's sniff() function.
        For every packet captured, calls _process_packet().
        Only captures IP packets (TCP + UDP) — ignores ARP, etc.
        """
        try:
            sniff(
                iface=INTERFACE,
                filter="ip",            # BPF filter — only IP packets
                prn=self._process_packet,  # callback per packet
                store=False,            # don't store in memory
                stop_filter=lambda p: not self.is_running
            )
        except PermissionError:
            print("[PacketSentinel] ❌ Permission denied!")
            print("[PacketSentinel]    Run with sudo: sudo python3 main.py")
        except Exception as e:
            print(f"[PacketSentinel] ❌ Sniffer error: {e}")

    # ────────────────────────────────────────────────────────────
    # PRIVATE — Process each captured packet
    # ────────────────────────────────────────────────────────────
    def _process_packet(self, packet):
        """
        Called automatically by scapy for every captured packet.
        Extracts fields and routes to baseline or detector.
        """
        try:
            # Only process packets that have an IP layer
            if not packet.haslayer(IP):
                return

            # ── Extract packet fields ────────────────────────────
            src_ip   = packet[IP].src
            dst_ip   = packet[IP].dst
            dst_port = 0
            protocol = "OTHER"

            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                protocol = "TCP"

                # Try to identify application protocol by port
                protocol = self._identify_protocol(dst_port, "TCP")

            elif packet.haslayer(UDP):
                dst_port = packet[UDP].dport
                protocol = self._identify_protocol(dst_port, "UDP")

            # ── Update stats ─────────────────────────────────────
            self.stats["total_packets"] += 1
            self._update_pps()

            # ── Feed to baseline during learning phase ───────────
            if self.baseline.is_learning:
                self.baseline.record_packet(src_ip, dst_port)
                return  # don't run detection during learning

            # ── Run detection after baseline is locked ───────────
            alerts = self.detector.analyze(src_ip, dst_ip, dst_port, protocol)

            if alerts:
                self.stats["total_alerts"] += len(alerts)
                for alert in alerts:
                    self._print_alert(alert)

        except Exception as e:
            # Never let a single bad packet crash the sniffer
            pass

    # ────────────────────────────────────────────────────────────
    # PRIVATE — Identify application protocol by port
    # ────────────────────────────────────────────────────────────
    def _identify_protocol(self, port: int, transport: str) -> str:
        """
        Maps port numbers to protocol names.
        This is how Wireshark and Snort identify protocols too.
        """
        PORT_MAP = {
            80   : "HTTP",
            443  : "HTTPS",
            22   : "SSH",
            21   : "FTP",
            25   : "SMTP",
            53   : "DNS",
            3306 : "MySQL",
            5432 : "PostgreSQL",
            8080 : "HTTP-ALT",
            8443 : "HTTPS-ALT",
            6379 : "Redis",
            27017: "MongoDB",
        }
        return PORT_MAP.get(port, transport)

    # ────────────────────────────────────────────────────────────
    # PRIVATE — Update packets per second counter
    # ────────────────────────────────────────────────────────────
    def _update_pps(self):
        """Updates the packets-per-second stat every second."""
        now = time.time()
        self._pps_counter += 1
        if now - self._last_pps_tick >= 1.0:
            self.stats["packets_per_sec"] = self._pps_counter
            self._pps_counter  = 0
            self._last_pps_tick = now

    # ────────────────────────────────────────────────────────────
    # PRIVATE — Print alert to terminal with color
    # ────────────────────────────────────────────────────────────
    def _print_alert(self, alert: dict):
        """Prints a formatted alert to terminal."""
        colors = {
            "LOW"      : "\033[94m",   # Blue
            "MEDIUM"   : "\033[93m",   # Yellow
            "HIGH"     : "\033[91m",   # Red
            "CRITICAL" : "\033[95m",   # Magenta
        }
        reset  = "\033[0m"
        color  = colors.get(alert["severity"], "")

        print(
            f"{color}[{alert['severity']}] {alert['timestamp']} | "
            f"{alert['rule']} | {alert['src_ip']} "
            f"({alert['country']}) | {alert['detail']}{reset}"
        )