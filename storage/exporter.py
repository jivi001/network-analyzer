import os
import csv
import json
from datetime import datetime
from typing import List, Optional, Any

try:
    from scapy.all import wrpcap, PcapWriter
except ImportError:
    wrpcap = None
    PcapWriter = None

from storage.models import PacketInfo, AlertInfo, HostInfo, StatsSnapshot
from utils.constants import APP_VERSION


class Exporter:
    """Production Export Manager for PCAP, CSV, and JSON formats."""

    SUPPORTED_FORMATS = (".pcap", ".csv", ".json")

    def __init__(self):
        pass

    def validate_export_path(self, filepath: str, export_dir: str = "exports") -> str:
        """Sanitize, resolve, and validate output file paths against path traversal."""
        if not filepath or not isinstance(filepath, str):
            raise ValueError(f"Invalid export filename: '{filepath}'")

        clean_path = filepath.strip()
        if ".." in clean_path:
            raise ValueError(f"Path traversal detected in export path: '{filepath}'")

        # Determine extension and validate
        ext = os.path.splitext(clean_path)[1].lower()
        if ext and ext not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported export format '{ext}'. Supported formats: {', '.join(self.SUPPORTED_FORMATS)}"
            )

        if not os.path.isabs(export_dir):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            export_dir = os.path.abspath(os.path.join(base_dir, export_dir))

        self.ensure_export_dir(export_dir)
        base_abs = os.path.abspath(export_dir)

        # If clean_path is an absolute path directly passed (e.g. from tests or explicit user config)
        if os.path.isabs(clean_path):
            target_abs = os.path.abspath(clean_path)
            # Prevent write into root directory or system directories outside valid parent
            parent_dir = os.path.dirname(target_abs)
            if not parent_dir or parent_dir == target_abs or clean_path in ("/etc/passwd", "C:\\Windows\\system32", "/"):
                raise ValueError(f"Path traversal detected in export path: '{filepath}'")
            self.ensure_export_dir(parent_dir)
            return target_abs

        # If clean_path starts with slash or root, reject
        if clean_path.startswith(("/", "\\")) or (len(clean_path) > 1 and clean_path[1] == ":"):
            raise ValueError(f"Path traversal detected in export path: '{filepath}'")

        filename = os.path.basename(clean_path)
        if not filename or filename in (".", ".."):
            raise ValueError(f"Invalid export filename: '{filepath}'")

        target_abs = os.path.abspath(os.path.join(export_dir, filename))
        if not target_abs.startswith(base_abs):
            raise ValueError(f"Path traversal detected in export path: '{filepath}'")

        return target_abs

    def ensure_export_dir(self, directory: str = "exports"):
        """Create export directory if needed."""
        if not os.path.isabs(directory):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            directory = os.path.abspath(os.path.join(base_dir, directory))
        os.makedirs(directory, exist_ok=True)

    def generate_filename(self, prefix: str, extension: str) -> str:
        """Generate timestamped filename."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = extension.lstrip(".")
        return f"{prefix}_{ts}.{ext}"

    def export_csv(
        self,
        filepath: str,
        packets: Optional[List[PacketInfo]] = None,
        alerts: Optional[List[AlertInfo]] = None,
        stats: Optional[StatsSnapshot] = None,
    ):
        """Export packets and/or alerts to structured CSV."""
        resolved_path = self.validate_export_path(filepath)
        self.ensure_export_dir(os.path.dirname(resolved_path) or ".")

        with open(resolved_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            if alerts and not packets:
                # Alerts-only CSV export
                writer.writerow([
                    "id", "timestamp", "severity", "rule_name", "message",
                    "src_ip", "dst_ip", "dst_port", "protocol"
                ])
                for a in alerts:
                    writer.writerow([
                        a.id, a.timestamp_str or a.timestamp, a.severity,
                        a.rule_name, a.message, a.src_ip, a.dst_ip, a.dst_port, a.protocol
                    ])
            else:
                # Standard packet event stream CSV
                writer.writerow([
                    "id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
                    "protocol", "length", "service", "info"
                ])
                for p in (packets or []):
                    writer.writerow([
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
                    ])

    def export_pcap(self, filepath: str, raw_packets: List[Any]):
        """Export raw Scapy packets or PacketInfo objects to a valid binary PCAP."""
        if not wrpcap:
            raise RuntimeError("Scapy wrpcap not available.")
        if not raw_packets:
            raise ValueError("No packets provided for PCAP export.")

        resolved_path = self.validate_export_path(filepath)
        self.ensure_export_dir(os.path.dirname(resolved_path) or ".")

        # Extract raw Scapy packets if PacketInfo instances are provided
        scapy_pkts = []
        for item in raw_packets:
            if hasattr(item, "raw_packet") and item.raw_packet is not None:
                scapy_pkts.append(item.raw_packet)
            elif hasattr(item, "haslayer") or hasattr(item, "build"):
                scapy_pkts.append(item)

        if not scapy_pkts:
            raise ValueError("No raw packet layer data available for PCAP export.")

        wrpcap(resolved_path, scapy_pkts)

    def export_json(
        self,
        filepath: str,
        alerts: Optional[List[AlertInfo]] = None,
        stats: Optional[StatsSnapshot] = None,
        hosts: Optional[List[HostInfo]] = None,
        packets: Optional[List[PacketInfo]] = None,
    ):
        """Export structured metadata, packets, alerts, hosts, and stats to valid JSON."""
        resolved_path = self.validate_export_path(filepath)
        self.ensure_export_dir(os.path.dirname(resolved_path) or ".")

        data = {
            "metadata": {
                "application": "my-sentinel",
                "version": APP_VERSION,
                "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_packets": len(packets) if packets else (stats.total_packets if stats else 0),
                "total_alerts": len(alerts) if alerts else 0,
                "total_hosts": len(hosts) if hosts else 0,
            },
            "stats": {
                "total_packets": stats.total_packets if stats else (len(packets) if packets else 0),
                "total_bytes": stats.total_bytes if stats else 0,
                "elapsed_seconds": stats.elapsed_seconds if stats else 0.0,
                "packets_per_sec": stats.packets_per_sec if stats else 0.0,
                "bytes_per_sec": stats.bytes_per_sec if stats else 0.0,
                "unique_hosts": stats.unique_hosts_total if stats else (len(hosts) if hosts else 0),
                "protocol_counts": stats.protocol_counts if stats else {},
                "top_talkers": stats.top_talkers if stats else [],
            }
            if stats
            else None,
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
                for a in (alerts or [])
            ],
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

        if packets:
            data["packets"] = [
                {
                    "id": p.id,
                    "timestamp": p.timestamp_str or p.timestamp,
                    "src_ip": p.src_ip,
                    "src_port": p.src_port,
                    "dst_ip": p.dst_ip,
                    "dst_port": p.dst_port,
                    "protocol": p.protocol,
                    "length": p.length,
                    "service": p.service,
                    "info": p.info,
                }
                for p in packets
            ]

        with open(resolved_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
