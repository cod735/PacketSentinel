# core/geoip.py
# PacketSentinel — GeoIP Country Lookup Engine
# Looks up which country an IP address belongs to.
# Uses MaxMind GeoLite2 offline database — no API calls needed.

import geoip2.database
import geoip2.errors
from config import GEOIP_DB_PATH


class GeoIPEngine:
    """
    Provides country lookup for any IP address.
    Uses a local offline database for fast, private lookups.
    """

    def __init__(self):
        self._reader = None
        self._available = False
        self._load_database()

    # ────────────────────────────────────────────────────────────
    # PRIVATE — load the database file on startup
    # ────────────────────────────────────────────────────────────
    def _load_database(self):
        """
        Loads the MaxMind GeoLite2 database from disk.
        If file is missing, GeoIP runs in degraded mode (returns Unknown).
        """
        try:
            self._reader   = geoip2.database.Reader(GEOIP_DB_PATH)
            self._available = True
            print("[PacketSentinel] 🌍 GeoIP database loaded successfully.")
        except FileNotFoundError:
            self._available = False
            print(f"[PacketSentinel] ⚠️  GeoIP database not found at {GEOIP_DB_PATH}")
            print("[PacketSentinel]    Country lookup will return 'Unknown'.")
        except Exception as e:
            self._available = False
            print(f"[PacketSentinel] ⚠️  GeoIP database error: {e}")

    # ────────────────────────────────────────────────────────────
    # PUBLIC — look up a single IP address
    # ────────────────────────────────────────────────────────────
    def lookup(self, ip: str) -> dict:
        """
        Returns country info for an IP address.

        Returns a dict:
        {
            "ip"           : "1.2.3.4",
            "country_name" : "United States",
            "country_code" : "US",
            "found"        : True
        }
        """
        # Skip private/local IP ranges — no point looking these up
        if self._is_private(ip):
            return {
                "ip"           : ip,
                "country_name" : "Private Network",
                "country_code" : "LAN",
                "found"        : False
            }

        if not self._available:
            return {
                "ip"           : ip,
                "country_name" : "Unknown",
                "country_code" : "??",
                "found"        : False
            }

        try:
            response = self._reader.country(ip)
            return {
                "ip"           : ip,
                "country_name" : response.country.name or "Unknown",
                "country_code" : response.country.iso_code or "??",
                "found"        : True
            }
        except geoip2.errors.AddressNotFoundError:
            # IP exists but not in the database
            return {
                "ip"           : ip,
                "country_name" : "Unknown",
                "country_code" : "??",
                "found"        : False
            }
        except Exception as e:
            return {
                "ip"           : ip,
                "country_name" : "Error",
                "country_code" : "??",
                "found"        : False
            }

    # ────────────────────────────────────────────────────────────
    # PUBLIC — check if an IP is from a high-risk country
    # ────────────────────────────────────────────────────────────
    def is_high_risk_country(self, ip: str) -> bool:
        """
        Returns True if IP is from a commonly flagged country.
        This is a basic signal — not a definitive block rule.
        In real tools this list comes from threat intel feeds.
        """
        # Common high-risk country codes used in security tools
        HIGH_RISK_COUNTRIES = {
            "KP",  # North Korea
            "IR",  # Iran
            "RU",  # Russia
            "CN",  # China
            "BY",  # Belarus
        }
        result = self.lookup(ip)
        return result["country_code"] in HIGH_RISK_COUNTRIES

    # ────────────────────────────────────────────────────────────
    # PRIVATE — detect private/local IP ranges
    # ────────────────────────────────────────────────────────────
    def _is_private(self, ip: str) -> bool:
        """
        Returns True if IP is a private/internal address.
        These never need GeoIP lookup.

        Private ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 127.0.0.0/8  (loopback)
        """
        try:
            parts = list(map(int, ip.split(".")))
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except Exception:
            return False

    # ────────────────────────────────────────────────────────────
    # CLEANUP — close database reader when done
    # ────────────────────────────────────────────────────────────
    def close(self):
        """Always close the reader when the program exits."""
        if self._reader:
            self._reader.close()