import threading
import time
from collections import Counter
from typing import Dict, List, Set, Any, Optional
from storage.models import PacketInfo, StatsSnapshot


class StatsAggregator:
    """Thread-safe Statistics Aggregator."""

    def __init__(self):
        self.lock = threading.RLock()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: Counter = Counter()
        self.ip_packets: Counter = Counter()
        self.ip_bytes: Counter = Counter()
        self.unique_src_ips: Set[str] = set()
        self.unique_dst_ips: Set[str] = set()

        self.packets_per_sec: float = 0.0
        self.bytes_per_sec: float = 0.0
        self._last_packets: int = 0
        self._last_bytes: int = 0
        self._last_time: float = time.time()
        self._start_time: float = time.time()

        self.rate_thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    def update(self, packet: PacketInfo):
        """Updates statistics with a new packet."""
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet.length
            self.protocol_counts[packet.protocol] += 1

            if packet.src_ip:
                self.ip_packets[packet.src_ip] += 1
                self.ip_bytes[packet.src_ip] += packet.length
                self.unique_src_ips.add(packet.src_ip)

            if packet.dst_ip:
                self.ip_packets[packet.dst_ip] += 1
                self.ip_bytes[packet.dst_ip] += packet.length
                self.unique_dst_ips.add(packet.dst_ip)

    def get_snapshot(self) -> StatsSnapshot:
        """Returns a snapshot of the current statistics."""
        with self.lock:
            unique_total = len(self.unique_src_ips | self.unique_dst_ips)
            elapsed = time.time() - self._start_time
            avg_size = (
                (self.total_bytes / self.total_packets)
                if self.total_packets > 0
                else 0.0
            )

            return StatsSnapshot(
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                packets_per_sec=self.packets_per_sec,
                bytes_per_sec=self.bytes_per_sec,
                avg_packet_size=avg_size,
                unique_src_hosts=len(self.unique_src_ips),
                unique_dst_hosts=len(self.unique_dst_ips),
                unique_hosts_total=unique_total,
                protocol_counts=dict(self.protocol_counts),
                protocol_percentages=self.get_protocol_distribution(),
                top_talkers=self.get_top_talkers(n=5),
                elapsed_seconds=elapsed,
            )

    def reset(self):
        """Resets all statistics."""
        with self.lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts.clear()
            self.ip_packets.clear()
            self.ip_bytes.clear()
            self.unique_src_ips.clear()
            self.unique_dst_ips.clear()
            self.packets_per_sec = 0.0
            self.bytes_per_sec = 0.0
            self._last_packets = 0
            self._last_bytes = 0
            self._last_time = time.time()
            self._start_time = time.time()

    def get_top_talkers(self, n: int = 5) -> List[Dict[str, Any]]:
        """Returns the top N talkers by packet count and byte volume."""
        with self.lock:
            top = self.ip_bytes.most_common(n)
            return [
                {"ip": ip, "bytes": b, "packets": self.ip_packets[ip]}
                for ip, b in top
            ]

    def get_protocol_distribution(self) -> Dict[str, float]:
        """Returns the protocol distribution as percentages."""
        with self.lock:
            if self.total_packets == 0:
                return {}
            return {
                proto: round((count / self.total_packets) * 100.0, 1)
                for proto, count in self.protocol_counts.items()
            }

    def start_rate_calculator(self):
        """Starts the background rate calculator thread."""
        if self._running.is_set():
            return
        self._running.set()
        self._last_time = time.time()
        self._last_packets = self.total_packets
        self._last_bytes = self.total_bytes
        self.rate_thread = threading.Thread(target=self._calc_loop, daemon=True)
        self.rate_thread.start()

    def stop_rate_calculator(self):
        """Stops the rate calculator thread."""
        self._running.clear()
        if self.rate_thread and self.rate_thread.is_alive():
            self.rate_thread.join(timeout=2.0)

    def _calc_loop(self):
        while self._running.is_set():
            time.sleep(1.0)
            with self.lock:
                current_time = time.time()
                elapsed = current_time - self._last_time
                if elapsed > 0:
                    current_pps = (self.total_packets - self._last_packets) / elapsed
                    current_bps = (self.total_bytes - self._last_bytes) / elapsed
                    
                    # Smooth rate using Exponential Moving Average (alpha=0.5)
                    self.packets_per_sec = (self.packets_per_sec * 0.5) + (current_pps * 0.5)
                    self.bytes_per_sec = (self.bytes_per_sec * 0.5) + (current_bps * 0.5)

                self._last_packets = self.total_packets
                self._last_bytes = self.total_bytes
                self._last_time = current_time
