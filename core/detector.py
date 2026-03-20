# core/detector.py
# PacketSentinel — Detection Engine
# Runs all 4 detection rules on every packet.

import time
import sqlite3
from collections import defaultdict
from config import (
    DB_PATH,
    BLOCKLIST_PATH,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
    EXPECTED_PROTOCOLS,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
from core.baseline import BaselineEngine
from core.geoip import GeoIPEngine


class DetectionEngine:
    """
    Runs 4 detection rules on every packet:
    1. Port Scan Detection
    2. Bandwidth Spike Detection
    3. Suspicious IP Detection
    4. Protocol Anomaly Detection
    """

    def __init__(self, baseline: BaselineEngine, geoip: GeoIPEngine):
        self.baseline = baseline
        self.geoip    = geoip

        # ── Port scan tracking ───────────────────────────────────
        self._port_scan_tracker = defaultdict(list)

        # ── Bandwidth tracking ───────────────────────────────────
        self._current_second_packets = 0
        self._last_bw_tick           = time.time()
        self._current_pps            = 0

        # ── Suspicious IP blocklist ──────────────────────────────
        self._blocklist = self._load_blocklist()

        # ── SQLite database setup ────────────────────────────────
        self._init_database()

        print(f"[PacketSentinel] 🔍 Detection engine ready.")
        print(f"[PacketSentinel] 📋 Blocklist loaded: {len(self._blocklist)} IPs")

    # ════════════════════════════════════════════════════════════
    # GLOBAL WHITELIST — never alert on these IPs
    # ════════════════════════════════════════════════════════════
    GLOBAL_WHITELIST = {
        '8.8.8.8',         # Google DNS
        '8.8.4.4',         # Google DNS 2
        '1.1.1.1',         # Cloudflare DNS
        '1.0.0.1',         # Cloudflare DNS 2
        '9.9.9.9',         # Quad9 DNS
        '127.0.0.1',       # Loopback
        '192.168.219.150', # VM IP
        '192.168.219.1',   # Gateway
        '192.168.219.2',   # VMware gateway
        '224.0.0.251',     # mDNS multicast
        '239.255.255.250', # SSDP multicast
    }

    # ════════════════════════════════════════════════════════════
    # MAIN ENTRY POINT
    # ════════════════════════════════════════════════════════════
    def analyze(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> list:
        """
        Analyzes a single packet against all 4 rules.
        Returns a list of alert dicts (empty if no alerts).
        """
        # Skip whitelisted IPs entirely
        if src_ip in self.GLOBAL_WHITELIST:
            return []

        alerts = []

        # Update bandwidth counter first
        self._update_bandwidth_counter()

        # Run all 4 rules
        alert1 = self._check_port_scan(src_ip, dst_port)
        alert2 = self._check_bandwidth_spike()
        alert3 = self._check_suspicious_ip(src_ip)
        alert4 = self._check_protocol_anomaly(src_ip, dst_port, protocol)

        # Collect any alerts that fired
        for alert in [alert1, alert2, alert3, alert4]:
            if alert:
                alerts.append(alert)
                self._save_alert(alert)

        return alerts

    # ════════════════════════════════════════════════════════════
    # RULE 1 — Port Scan Detection
    # ════════════════════════════════════════════════════════════
    def _check_port_scan(self, src_ip: str, dst_port: int):
        """
        Fires if one IP hits too many unique ports in a short window.
        """
        now = time.time()

        self._port_scan_tracker[src_ip].append((dst_port, now))

        # Remove entries older than the scan window
        self._port_scan_tracker[src_ip] = [
            (port, ts) for port, ts in self._port_scan_tracker[src_ip]
            if now - ts <= PORT_SCAN_WINDOW
        ]

        # Count unique ports hit in the window
        unique_ports = set(
            port for port, ts in self._port_scan_tracker[src_ip]
        )

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            self._port_scan_tracker[src_ip] = []
            severity = SEVERITY_HIGH if len(unique_ports) > 30 else SEVERITY_MEDIUM
            return self._build_alert(
                rule     = "Port Scan Detected",
                src_ip   = src_ip,
                detail   = f"{len(unique_ports)} unique ports scanned in {PORT_SCAN_WINDOW}s",
                severity = severity
            )
        return None

    # ════════════════════════════════════════════════════════════
    # RULE 2 — Bandwidth Spike Detection
    # ════════════════════════════════════════════════════════════
    def _check_bandwidth_spike(self):
        """
        Fires if current packets/sec exceeds baseline spike threshold.
        """
        if self.baseline.is_bandwidth_spike(self._current_pps):
            return self._build_alert(
                rule     = "Bandwidth Spike Detected",
                src_ip   = "N/A",
                detail   = f"Traffic at {self._current_pps} pkt/s exceeds threshold of {self.baseline.spike_threshold:.1f}",
                severity = SEVERITY_HIGH
            )
        return None

    # ════════════════════════════════════════════════════════════
    # RULE 3 — Suspicious IP Detection
    # ════════════════════════════════════════════════════════════
    def _check_suspicious_ip(self, src_ip: str):
        """
        Fires if source IP is in the blocklist OR from a high-risk country.
        """
        # Whitelist check (extra safety)
        if src_ip in self.GLOBAL_WHITELIST:
            return None

        # Layer 1 — check local blocklist
        if src_ip in self._blocklist:
            geo = self.geoip.lookup(src_ip)
            return self._build_alert(
                rule     = "Suspicious IP - Blocklist Match",
                src_ip   = src_ip,
                detail   = f"IP matched blocklist | Country: {geo['country_name']} ({geo['country_code']})",
                severity = SEVERITY_CRITICAL
            )

        # Layer 2 — check GeoIP high risk country
        if self.geoip.is_high_risk_country(src_ip):
            geo = self.geoip.lookup(src_ip)
            return self._build_alert(
                rule     = "Suspicious IP - High Risk Country",
                src_ip   = src_ip,
                detail   = f"Traffic from high-risk country: {geo['country_name']} ({geo['country_code']})",
                severity = SEVERITY_HIGH
            )

        return None

    # ════════════════════════════════════════════════════════════
    # RULE 4 — Protocol Anomaly Detection
    # ════════════════════════════════════════════════════════════
    def _check_protocol_anomaly(self, src_ip: str, dst_port: int, protocol: str):
        """
        Fires if a port is being used with an unexpected protocol.
        """
        if dst_port in EXPECTED_PROTOCOLS:
            expected = EXPECTED_PROTOCOLS[dst_port]
            if protocol.upper() != expected.upper():
                return self._build_alert(
                    rule     = "Protocol Anomaly Detected",
                    src_ip   = src_ip,
                    detail   = f"Port {dst_port} expected {expected} but got {protocol}",
                    severity = SEVERITY_MEDIUM
                )
        return None

    # ════════════════════════════════════════════════════════════
    # HELPERS
    # ════════════════════════════════════════════════════════════
    def _update_bandwidth_counter(self):
        """Updates packets-per-second counter every second."""
        now = time.time()
        self._current_second_packets += 1
        if now - self._last_bw_tick >= 1.0:
            self._current_pps            = self._current_second_packets
            self._current_second_packets = 0
            self._last_bw_tick           = now

    def _build_alert(self, rule: str, src_ip: str, detail: str, severity: str) -> dict:
        """Builds a standard alert dictionary."""
        geo = self.geoip.lookup(src_ip) if src_ip != "N/A" else {}
        return {
            "timestamp"    : time.strftime("%Y-%m-%d %H:%M:%S"),
            "rule"         : rule,
            "src_ip"       : src_ip,
            "country"      : geo.get("country_name", "N/A"),
            "country_code" : geo.get("country_code", "??"),
            "detail"       : detail,
            "severity"     : severity,
        }

    def _load_blocklist(self) -> set:
        """Loads bad IPs from blocklist.txt into a set for O(1) lookup."""
        blocklist = set()
        try:
            with open(BLOCKLIST_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        blocklist.add(line)
        except FileNotFoundError:
            print(f"[PacketSentinel] ⚠️  Blocklist file not found. Creating empty one.")
            open(BLOCKLIST_PATH, "w").close()
        return blocklist

    # ════════════════════════════════════════════════════════════
    # DATABASE
    # ════════════════════════════════════════════════════════════
    def _init_database(self):
        """Creates the alerts table in SQLite if it doesn't exist."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT NOT NULL,
                rule         TEXT NOT NULL,
                src_ip       TEXT,
                country      TEXT,
                country_code TEXT,
                detail       TEXT,
                severity     TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _save_alert(self, alert: dict):
        """Saves a single alert to the SQLite database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts
                (timestamp, rule, src_ip, country, country_code, detail, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["timestamp"],
                alert["rule"],
                alert["src_ip"],
                alert["country"],
                alert["country_code"],
                alert["detail"],
                alert["severity"],
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[PacketSentinel] ⚠️  DB save error: {e}")

    def get_recent_alerts(self, limit: int = 100) -> list:
        """Fetches recent alerts from DB — used by Flask dashboard."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, rule, src_ip, country, country_code, detail, severity
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [
                {
                    "timestamp"    : r[0],
                    "rule"         : r[1],
                    "src_ip"       : r[2],
                    "country"      : r[3],
                    "country_code" : r[4],
                    "detail"       : r[5],
                    "severity"     : r[6],
                }
                for r in rows
            ]
        except Exception as e:
            print(f"[PacketSentinel] ⚠️  DB read error: {e}")
            return []