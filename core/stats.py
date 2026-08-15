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
        self.unique_hosts: Set[str] = set()

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
                self.unique_hosts.add(packet.src_ip)

            if packet.dst_ip:
                self.ip_packets[packet.dst_ip] += 1
                self.ip_bytes[packet.dst_ip] += packet.length
                self.unique_dst_ips.add(packet.dst_ip)
                self.unique_hosts.add(packet.dst_ip)

    def get_snapshot(self) -> StatsSnapshot:
        """Returns a snapshot of the current statistics without long-held locks."""
        with self.lock:
            total_pkts = self.total_packets
            total_bytes = self.total_bytes
            pps = self.packets_per_sec
            bps = self.bytes_per_sec
            num_src = len(self.unique_src_ips)
            num_dst = len(self.unique_dst_ips)
            unique_total = len(self.unique_hosts)
            proto_counts = dict(self.protocol_counts)
            top_raw = self.ip_bytes.most_common(5)
            top_talkers = [
                {"ip": ip, "bytes": b, "packets": self.ip_packets[ip]}
                for ip, b in top_raw
            ]

        # Heavy / derived calculations done outside lock
        elapsed = time.time() - self._start_time
        avg_size = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
        proto_pcts = (
            {proto: round((count / total_pkts) * 100.0, 1) for proto, count in proto_counts.items()}
            if total_pkts > 0 else {}
        )

        return StatsSnapshot(
            total_packets=total_pkts,
            total_bytes=total_bytes,
            packets_per_sec=pps,
            bytes_per_sec=bps,
            avg_packet_size=avg_size,
            unique_src_hosts=num_src,
            unique_dst_hosts=num_dst,
            unique_hosts_total=unique_total,
            protocol_counts=proto_counts,
            protocol_percentages=proto_pcts,
            top_talkers=top_talkers,
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
            self.unique_hosts.clear()
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
            total = self.total_packets
            counts = dict(self.protocol_counts)
        return {
            proto: round((count / total) * 100.0, 1)
            for proto, count in counts.items()
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
