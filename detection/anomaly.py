"""
Anomaly detection engine for my-sentinel.
"""
import math
import time
import threading
from collections import defaultdict
from typing import Optional
from storage.models import PacketInfo, AlertInfo


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not value:
        return 0.0

    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log(count / length, 2) for count in counts.values())


class AnomalyDetector:
    """Detects network anomalies like port scans and DNS exfiltration."""

    def __init__(self, max_hosts: int = 10000, max_beacon_pairs: int = 5000):
        self.lock = threading.Lock()

        # Port scan state: src_ip -> {'ports': set(), 'window_start': float}
        self.scan_state: dict[str, dict] = defaultdict(
            lambda: {"ports": set(), "window_start": time.time()}
        )
        self.scan_threshold = 10
        self.scan_window = 60.0
        self.max_hosts = max_hosts

        # Beaconing state: (src_ip, dst_ip) -> list of float timestamps
        self.beacon_state: dict[tuple[str, str], list[float]] = defaultdict(list)
        self.max_beacon_pairs = max_beacon_pairs

    def reset(self):
        """Clear all state."""
        with self.lock:
            self.scan_state.clear()
            self.beacon_state.clear()

    def _prune_state_if_needed(self, current_ts: float):
        """Evict expired or excess hosts and beacon pairs under lock."""
        if len(self.scan_state) >= self.max_hosts:
            expired = [
                ip for ip, data in self.scan_state.items()
                if current_ts - data["window_start"] > self.scan_window
            ]
            for ip in expired:
                del self.scan_state[ip]
            if len(self.scan_state) >= self.max_hosts:
                # Remove oldest window_start entries to keep size strictly within max_hosts - 1 before new insert
                sorted_ips = sorted(
                    self.scan_state.keys(),
                    key=lambda ip: self.scan_state[ip]["window_start"]
                )
                for ip in sorted_ips[: len(self.scan_state) - self.max_hosts + 1]:
                    del self.scan_state[ip]

        if len(self.beacon_state) >= self.max_beacon_pairs:
            # Remove pairs with oldest latest timestamp
            sorted_pairs = sorted(
                self.beacon_state.keys(),
                key=lambda k: self.beacon_state[k][-1] if self.beacon_state[k] else 0
            )
            for k in sorted_pairs[: len(self.beacon_state) - self.max_beacon_pairs + 1]:
                del self.beacon_state[k]

    def check_dns_exfiltration(self, packet: PacketInfo) -> Optional[AlertInfo]:
        """Entropy-based DNS tunnel detection."""
        if packet.protocol != "DNS" or not packet.dns_query:
            return None

        query = packet.dns_query
        subdomain = query.split(".")[0] if "." in query else query

        if len(subdomain) <= 20:
            return None

        entropy = shannon_entropy(subdomain)

        if entropy > 3.5:
            return AlertInfo(
                rule_name="DNS Exfiltration Tunnel",
                severity="CRITICAL",
                message=f"DNS Exfiltration: {query} (entropy={entropy:.2f})",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                protocol="DNS",
                timestamp=packet.timestamp,
                timestamp_str=packet.timestamp_str,
            )
        return None

    def check_beaconing(self, packet: PacketInfo) -> Optional[AlertInfo]:
        """Detect C2 beaconing patterns."""
        if not packet.src_ip or not packet.dst_ip:
            return None

        ts = packet.timestamp or time.time()

        with self.lock:
            self._prune_state_if_needed(ts)
            key = (packet.src_ip, packet.dst_ip)
            self.beacon_state[key].append(ts)

            timestamps = self.beacon_state[key]
            if len(timestamps) > 100:
                self.beacon_state[key] = timestamps[-100:]

            if len(self.beacon_state[key]) > 5:
                # Calculate intervals between consecutive timestamps
                intervals = [
                    self.beacon_state[key][i] - self.beacon_state[key][i - 1]
                    for i in range(1, len(self.beacon_state[key]))
                ]
                mean_interval = sum(intervals) / len(intervals)
                variance = (
                    sum((x - mean_interval) ** 2 for x in intervals)
                    / len(intervals)
                )
                stddev = math.sqrt(variance) if variance > 0 else 0

                if stddev < 0.5 and mean_interval > 1.0:
                    return AlertInfo(
                        rule_name="C2 Beaconing",
                        severity="HIGH",
                        message=f"Beaconing detected from {packet.src_ip} to {packet.dst_ip} (interval={mean_interval:.2f}s)",
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        dst_port=packet.dst_port,
                        protocol=packet.protocol,
                        timestamp=packet.timestamp,
                        timestamp_str=packet.timestamp_str,
                    )
        return None

    def check_port_scan(self, packet: PacketInfo) -> Optional[AlertInfo]:
        """Detect single source scanning multiple ports."""
        if packet.protocol not in ("TCP", "UDP") or not packet.dst_port:
            return None

        ts = packet.timestamp or time.time()

        with self.lock:
            self._prune_state_if_needed(ts)
            state = self.scan_state[packet.src_ip]

            if ts - state["window_start"] > self.scan_window:
                state["ports"].clear()
                state["window_start"] = ts

            state["ports"].add(packet.dst_port)

            if len(state["ports"]) > self.scan_threshold:
                port_count = len(state["ports"])
                alert = AlertInfo(
                    rule_name="Port Scan",
                    severity="HIGH",
                    message=f"Port scan detected from {packet.src_ip} ({port_count} ports touched)",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    timestamp=packet.timestamp,
                    timestamp_str=packet.timestamp_str,
                )
                state["ports"].clear()  # Reset window after alert
                return alert

        return None

