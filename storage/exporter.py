import os
import csv
import json
from datetime import datetime
from typing import List, Optional

try:
    from scapy.all import wrpcap
except ImportError:
    wrpcap = None

from storage.models import PacketInfo, AlertInfo, HostInfo, StatsSnapshot
from utils.constants import format_bytes


class Exporter:
    """Export Manager for exporting packets, alerts, and stats."""

    def __init__(self):
        pass

    def ensure_export_dir(self, directory: str = "exports"):
        """Create directory if needed."""
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            print(f"Failed to create directory {directory}: {e}")

    def generate_filename(self, prefix: str, extension: str) -> str:
        """Generate timestamped filename."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefix}_{ts}.{extension.lstrip('.')}"

    def export_csv(
        self,
        filepath: str,
        packets: List[PacketInfo],
        stats: Optional[StatsSnapshot] = None,
    ):
        """Export packets to CSV."""
        self.ensure_export_dir(os.path.dirname(filepath) or ".")
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "id",
                        "timestamp",
                        "src_ip",
                        "src_port",
                        "dst_ip",
                        "dst_port",
                        "protocol",
                        "length",
                        "service",
                        "info",
                    ]
                )
                for p in packets:
                    writer.writerow(
                        [
                            p.id,
                            p.timestamp_str or p.timestamp,
                            p.src_ip,
                            p.src_port,
                            p.dst_ip,
                            p.dst_port,
                            p.protocol,
                            p.length,
                            p.service,
                            p.info,
                        ]
                    )
        except Exception as e:
            print(f"Error exporting CSV: {e}")

    def export_pcap(self, filepath: str, raw_packets: list):
        """Export raw packets to PCAP using Scapy."""
        if not wrpcap:
            print("Error exporting PCAP: Scapy wrpcap not available.")
            return
        self.ensure_export_dir(os.path.dirname(filepath) or ".")
        try:
            wrpcap(filepath, raw_packets)
        except Exception as e:
            print(f"Error exporting PCAP: {e}")

    def export_json(
        self,
        filepath: str,
        alerts: List[AlertInfo],
        stats: Optional[StatsSnapshot] = None,
        hosts: Optional[List[HostInfo]] = None,
    ):
        """Export alerts, stats, and hosts to JSON."""
        self.ensure_export_dir(os.path.dirname(filepath) or ".")
        try:
            data = {
                "metadata": {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                "alerts": [
                    {
                        "id": a.id,
                        "session_id": a.session_id,
                        "timestamp": a.timestamp_str or a.timestamp,
                        "severity": a.severity,
                        "rule_name": a.rule_name,
                        "message": a.message,
                        "src_ip": a.src_ip,
                        "dst_ip": a.dst_ip,
                        "dst_port": a.dst_port,
                        "protocol": a.protocol,
                    }
                    for a in alerts
                ]
                if alerts
                else [],
                "stats": {
                    "total_packets": stats.total_packets if stats else 0,
                    "total_bytes": stats.total_bytes if stats else 0,
                    "unique_hosts": stats.unique_hosts_total if stats else 0,
                    "protocol_counts": stats.protocol_counts if stats else {},
                    "top_talkers": stats.top_talkers if stats else [],
                }
                if stats
                else None,
                "hosts": [
                    {
                        "id": h.id,
                        "ip_address": h.ip_address,
                        "mac_address": h.mac_address,
                        "hostname": h.hostname,
                        "open_ports": h.open_ports,
                        "services": h.services,
                        "os_guess": h.os_guess,
                        "first_seen": str(h.first_seen),
                        "last_seen": str(h.last_seen),
                        "source": h.source,
                        "packet_count": h.packet_count,
                        "byte_count": h.byte_count,
                        "state": h.state,
                    }
                    for h in (hosts or [])
                ],
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Error exporting JSON: {e}")
