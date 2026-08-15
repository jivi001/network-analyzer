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
    if not value or not isinstance(value, str):
        return 0.0
    length = len(value)
    if length <= 1:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    ent = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return max(0.0, ent)


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

        # DNS Exfiltration state: (src_ip, parent_domain) -> {'count': int, 'window_start': float, 'labels': set}
        self.dns_exfil_state: dict[tuple[str, str], dict] = {}

    def reset(self):
        """Clear all state."""
        with self.lock:
            self.scan_state.clear()
            self.beacon_state.clear()
            self.dns_exfil_state.clear()

    def _prune_state_if_needed(self, current_ts: float):
        """Evict expired or excess hosts, beacon pairs, and DNS exfil state under lock."""
        if len(self.scan_state) >= self.max_hosts:
            expired = [
                ip for ip, data in self.scan_state.items()
                if current_ts - data["window_start"] > self.scan_window
            ]
            for ip in expired:
                del self.scan_state[ip]
            if len(self.scan_state) >= self.max_hosts:
                sorted_ips = sorted(
                    self.scan_state.keys(),
                    key=lambda ip: self.scan_state[ip]["window_start"]
                )
                for ip in sorted_ips[: len(self.scan_state) - self.max_hosts + 1]:
                    del self.scan_state[ip]

        if len(self.beacon_state) >= self.max_beacon_pairs:
            sorted_pairs = sorted(
                self.beacon_state.keys(),
                key=lambda k: self.beacon_state[k][-1] if self.beacon_state[k] else 0
            )
            for k in sorted_pairs[: len(self.beacon_state) - self.max_beacon_pairs + 1]:
                del self.beacon_state[k]

        # Prune DNS exfil state
        if len(self.dns_exfil_state) >= self.max_hosts:
            expired_dns = [
                k for k, v in self.dns_exfil_state.items()
                if current_ts - v.get("window_start", 0) > 60.0
            ]
            for k in expired_dns:
                del self.dns_exfil_state[k]
            if len(self.dns_exfil_state) >= self.max_hosts:
                sorted_dns = sorted(
                    self.dns_exfil_state.keys(),
                    key=lambda k: self.dns_exfil_state[k].get("window_start", 0)
                )
                for k in sorted_dns[: len(self.dns_exfil_state) - self.max_hosts + 1]:
                    del self.dns_exfil_state[k]

    def check_dns_exfiltration(self, packet: PacketInfo) -> Optional[AlertInfo]:
        """Multi-signal entropy & volume based DNS tunnel detection.

        Severity escalation:
          - 1 suspicious query         -> WARNING  (single signal, could be UUID/CDN)
          - 2 unique high-ent labels    -> HIGH     (repeated suspicious activity)
          - 3+ unique or 5+ total       -> CRITICAL (sustained exfiltration tunnel)
        """
        if packet.protocol != "DNS" or not getattr(packet, "dns_query", None):
            return None

        query = str(packet.dns_query).strip()
        if not query:
            return None

        clean_q = query.rstrip(".")
        labels = [lbl for lbl in clean_q.split(".") if lbl]
        if not labels:
            return None

        # Inspect all subdomain labels (exclude TLD/registered domain)
        candidate_labels = labels[:-1] if len(labels) >= 2 else labels

        suspicious_candidates = []
        for lbl in candidate_labels:
            if len(lbl) > 20:
                ent = shannon_entropy(lbl.lower())
                if ent > 3.5:
                    suspicious_candidates.append((lbl, ent))

        if not suspicious_candidates:
            return None

        best_label, max_ent = max(suspicious_candidates, key=lambda x: x[1])
        packet.entropy = round(max_ent, 2)

        ts = packet.timestamp if isinstance(packet.timestamp, (int, float)) and packet.timestamp > 0 else time.time()
        parent_domain = ".".join(labels[-2:]) if len(labels) >= 2 else labels[-1]

        with self.lock:
            self._prune_state_if_needed(ts)
            state_key = (packet.src_ip or "unknown", parent_domain.lower())

            if state_key not in self.dns_exfil_state:
                self.dns_exfil_state[state_key] = {
                    "count": 0,
                    "window_start": ts,
                    "labels": set(),
                }

            dstate = self.dns_exfil_state[state_key]
            if ts - dstate["window_start"] > 60.0:
                dstate["count"] = 0
                dstate["window_start"] = ts
                dstate["labels"].clear()

            dstate["count"] += 1
            if len(dstate["labels"]) < 100:
                dstate["labels"].add(best_label.lower())

            unique_count = len(dstate["labels"])
            total_count = dstate["count"]

            # Severity escalation based on multi-signal correlation
            if unique_count >= 3 or total_count >= 5:
                severity = "CRITICAL"
                message = f"DNS Exfiltration Tunnel: {query} (entropy={max_ent:.2f}, unique_labels={unique_count}, queries={total_count})"
            elif unique_count >= 2:
                severity = "HIGH"
                message = f"DNS Exfiltration (repeated): {query} (entropy={max_ent:.2f}, unique_labels={unique_count})"
            else:
                severity = "WARNING"
                message = f"Suspicious DNS query: {query} (entropy={max_ent:.2f}, single signal)"

            return AlertInfo(
                rule_name="DNS Exfiltration Tunnel",
                severity=severity,
                message=message,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                protocol="DNS",
                timestamp=packet.timestamp,
                timestamp_str=packet.timestamp_str,
            )

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

