"""
ARP Spoof Detection for my-sentinel.
"""
from typing import Optional
from storage.models import PacketInfo, AlertInfo


class ArpMonitor:
    """Detects ARP cache poisoning attempts."""

    def __init__(self):
        self.arp_table: dict[str, str] = {}

    def reset(self):
        """Clear ARP table."""
        self.arp_table.clear()

    def get_arp_table(self) -> dict:
        """Return current IP to MAC bindings."""
        return self.arp_table.copy()

    def check(self, packet: PacketInfo) -> Optional[AlertInfo]:
        """Check ARP packet for spoofing."""
        if packet.protocol != "ARP":
            return None

        src_ip = packet.src_ip
        mac = packet.src_mac

        if not src_ip or not mac:
            return None

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
            old_mac = self.arp_table[src_ip]
            if old_mac != mac:
                # Spoof detected!
                self.arp_table[src_ip] = mac  # Update table
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
            self.arp_table[src_ip] = mac

        return None
