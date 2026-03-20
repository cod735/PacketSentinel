# core/baseline.py
# PacketSentinel — Baseline Learning Engine
# Observes normal traffic first, then locks the baseline for anomaly detection.

import time
import threading
from collections import defaultdict
from config import BASELINE_DURATION, BANDWIDTH_SPIKE_MULTIPLIER


class BaselineEngine:
    """
    Observes network traffic during a learning period and builds
    a picture of what 'normal' looks like for this network.
    """

    def __init__(self):
        # ── Learning state ──────────────────────────────────────
        self.is_learning       = True    # True during baseline window
        self.is_ready          = False   # True after baseline is locked
        self.start_time        = time.time()

        # ── Raw data collected during learning ──────────────────
        self._packet_counts    = []      # packets per second samples
        self._seen_ips         = defaultdict(int)   # ip → count
        self._seen_ports       = defaultdict(int)   # port → count
        self._current_second   = 0      # packets in current second
        self._last_tick        = time.time()

        # ── Locked baseline values (set after learning) ─────────
        self.avg_packets_per_sec  = 0
        self.max_packets_per_sec  = 0
        self.spike_threshold      = 0    # above this = bandwidth spike
        self.normal_ips           = set()
        self.normal_ports         = set()

        # ── Thread lock (safe for multi-threaded use) ────────────
        self._lock = threading.Lock()

        # Start the background timer that locks baseline after duration
        self._start_baseline_timer()

    # ────────────────────────────────────────────────────────────
    # PUBLIC METHOD — called by sniffer for every packet
    # ────────────────────────────────────────────────────────────
    def record_packet(self, src_ip, dst_port):
        """
        Called for every packet during the learning phase.
        Records IPs, ports, and packet rate per second.
        """
        if not self.is_learning:
            return  # baseline is locked, stop recording

        with self._lock:
            now = time.time()

            # Count packets per second
            if now - self._last_tick >= 1.0:
                # One second has passed — save this sample
                self._packet_counts.append(self._current_second)
                self._current_second = 0
                self._last_tick = now
            else:
                self._current_second += 1

            # Track which IPs and ports are normal
            self._seen_ips[src_ip]     += 1
            self._seen_ports[dst_port] += 1

    # ────────────────────────────────────────────────────────────
    # PUBLIC METHOD — is this packet count a spike?
    # ────────────────────────────────────────────────────────────
    def is_bandwidth_spike(self, current_packets_per_sec):
        """
        Returns True if current traffic exceeds the spike threshold.
        Only works after baseline is locked (is_ready = True).
        """
        if not self.is_ready:
            return False  # still learning, never alert yet
        return current_packets_per_sec > self.spike_threshold

    # ────────────────────────────────────────────────────────────
    # PUBLIC METHOD — how long is left in learning phase?
    # ────────────────────────────────────────────────────────────
    def time_remaining(self):
        """Returns seconds remaining in the baseline learning window."""
        elapsed = time.time() - self.start_time
        remaining = BASELINE_DURATION - elapsed
        return max(0, int(remaining))

    # ────────────────────────────────────────────────────────────
    # PRIVATE — lock the baseline after learning period ends
    # ────────────────────────────────────────────────────────────
    def _lock_baseline(self):
        """
        Called automatically after BASELINE_DURATION seconds.
        Calculates averages and locks the baseline.
        """
        with self._lock:
            self.is_learning = False

            if self._packet_counts:
                self.avg_packets_per_sec = sum(self._packet_counts) / len(self._packet_counts)
                self.max_packets_per_sec = max(self._packet_counts)
            else:
                # No traffic observed — set safe defaults
                self.avg_packets_per_sec = 10
                self.max_packets_per_sec = 20

            # Spike threshold = average × multiplier from config
            # Example: avg=100, multiplier=2.0 → alert if > 200 packets/sec
            self.spike_threshold = self.avg_packets_per_sec * BANDWIDTH_SPIKE_MULTIPLIER

            # IPs seen more than once = normal IPs
            self.normal_ips = {
                ip for ip, count in self._seen_ips.items() if count > 1
            }

            # Ports seen more than once = normal ports
            self.normal_ports = {
                port for port, count in self._seen_ports.items() if count > 1
            }

            self.is_ready = True

            print(f"\n[PacketSentinel] ✅ Baseline locked!")
            print(f"  Avg packets/sec : {self.avg_packets_per_sec:.1f}")
            print(f"  Max packets/sec : {self.max_packets_per_sec}")
            print(f"  Spike threshold : {self.spike_threshold:.1f}")
            print(f"  Normal IPs seen : {len(self.normal_ips)}")
            print(f"  Normal ports    : {len(self.normal_ports)}")
            print(f"[PacketSentinel] 🚀 Detection is now ACTIVE\n")

    def _start_baseline_timer(self):
        """Starts a background thread that locks baseline after duration."""
        timer = threading.Timer(BASELINE_DURATION, self._lock_baseline)
        timer.daemon = True   # dies when main program exits
        timer.start()
        print(f"[PacketSentinel] 🧠 Learning baseline for {BASELINE_DURATION} seconds...")
        print(f"[PacketSentinel] ⏳ Detection will start after learning completes.\n")