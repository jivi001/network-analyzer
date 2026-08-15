"""
ARP Spoof Detection for my-sentinel.
"""
import time
from typing import Optional
from storage.models import PacketInfo, AlertInfo


class ArpMonitor:
    """Detects ARP cache poisoning attempts with bounded state."""

    def __init__(self, max_hosts: int = 10000, ttl: float = 600.0):
        # ip -> {'mac': str, 'last_seen': float}
        self.arp_table: dict[str, dict] = {}
        self.max_hosts = max(1, max_hosts)
        self.ttl = ttl  # seconds before an entry is eligible for eviction

    def reset(self):
        """Clear ARP table."""
        self.arp_table.clear()

    def get_arp_table(self) -> dict:
        """Return current IP to MAC bindings."""
        return {ip: entry['mac'] for ip, entry in self.arp_table.items()}

    def _prune(self, now: float):
        """Evict expired entries, then oldest entries if still over capacity."""
        if len(self.arp_table) < self.max_hosts:
            return

        # 1. Remove TTL-expired entries
        expired = [ip for ip, entry in self.arp_table.items()
                   if now - entry['last_seen'] > self.ttl]
        for ip in expired:
            del self.arp_table[ip]

        # 2. If still at capacity, evict oldest-seen entries
        if len(self.arp_table) >= self.max_hosts:
            sorted_ips = sorted(
                self.arp_table.keys(),
                key=lambda ip: self.arp_table[ip]['last_seen']
            )
            to_remove = len(self.arp_table) - self.max_hosts + 1
            for ip in sorted_ips[:to_remove]:
                del self.arp_table[ip]

    def check(self, packet: PacketInfo) -> Optional[AlertInfo]:
        """Check ARP packet for spoofing."""
        if packet.protocol != "ARP":
            return None

        src_ip = packet.src_ip
        mac = packet.src_mac

        if not src_ip or not mac:
            return None

        now = packet.timestamp if isinstance(packet.timestamp, (int, float)) and packet.timestamp > 0 else time.time()

        # Gratuitous ARP
        if src_ip == packet.dst_ip:
            return AlertInfo(
                rule_name="Gratuitous ARP",
                severity="INFO",
                message=f"Gratuitous ARP from {src_ip} ({mac})",
                src_ip=src_ip,
                dst_ip=packet.dst_ip,
                protocol="ARP",
                timestamp=packet.timestamp,
                timestamp_str=packet.timestamp_str,
            )

        if src_ip in self.arp_table:
            old_mac = self.arp_table[src_ip]['mac']
            self.arp_table[src_ip]['last_seen'] = now
            if old_mac != mac:
                # Spoof detected!
                self.arp_table[src_ip]['mac'] = mac
                packet.old_mac = old_mac
                packet.new_mac = mac
                return AlertInfo(
                    rule_name="ARP Spoofing",
                    severity="CRITICAL",
                    message=f"ARP Spoof detected! {src_ip} changed from {old_mac} to {mac}",
                    src_ip=src_ip,
                    dst_ip=packet.dst_ip,
                    protocol="ARP",
                    timestamp=packet.timestamp,
                    timestamp_str=packet.timestamp_str,
                )
        else:
            self._prune(now)
            self.arp_table[src_ip] = {'mac': mac, 'last_seen': now}

        return None

