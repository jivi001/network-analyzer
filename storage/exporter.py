import os
import re
import csv
import json
from datetime import datetime
from pathlib import Path
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
    DEFAULT_EXPORT_DIR = "exports"

    # Prohibited root and sensitive system directories (lowercased)
    PROHIBITED_DIRECTORIES_POSIX = frozenset({
        "/", "/etc", "/bin", "/sbin", "/usr", "/boot", "/dev",
        "/proc", "/sys", "/root", "/var/run", "/lib", "/lib64",
        "/lost+found",
    })

    PROHIBITED_DIRECTORIES_WINDOWS = frozenset({
        "windows", "winnt", "system32", "program files",
        "program files (x86)", "recovery", "boot",
    })

    def __init__(self, default_export_dir: str = "exports", allow_absolute: bool = True):
        self.default_export_dir = default_export_dir
        self.allow_absolute = allow_absolute

    def _verify_not_prohibited_directory(self, target_path: Path, raw_path: str) -> None:
        """Prevent writing into root or sensitive system directories."""
        # 1. Reject if target is equal to its parent (i.e. root filesystem / or drive root)
        if target_path == target_path.parent or str(target_path) in ("/", "\\"):
            raise ValueError(f"Path traversal detected in export path: '{raw_path}'")

        # 2. Check Windows prohibited directories using PureWindowsPath
        from pathlib import PureWindowsPath
        win_parts = [p.lower() for p in PureWindowsPath(raw_path).parts]
        if win_parts and re.match(r"^[a-zA-Z]:\\?$", win_parts[0]) and len(win_parts) <= 2:
            raise ValueError(f"Path traversal detected in export path: '{raw_path}'")

        for prohibited in self.PROHIBITED_DIRECTORIES_WINDOWS:
            if prohibited in win_parts:
                raise ValueError(f"Path traversal detected in export path: '{raw_path}'")

        # 3. Check POSIX prohibited directories
        target_str = str(target_path)
        for prohibited in self.PROHIBITED_DIRECTORIES_POSIX:
            if prohibited == "/":
                if target_str == "/" or target_path.parent == Path("/"):
                    raise ValueError(f"Path traversal detected in export path: '{raw_path}'")
            else:
                prohibited_path = Path(prohibited)
                try:
                    is_rel = target_path == prohibited_path or target_path.is_relative_to(prohibited_path)
                except ValueError:
                    is_rel = False
                if is_rel:
                    raise ValueError(f"Path traversal detected in export path: '{raw_path}'")

    def validate_export_path(
        self,
        filepath: str,
        export_dir: Optional[str] = "exports",
        allow_absolute: Optional[bool] = None,
    ) -> str:
        """Sanitize, resolve, and validate output file paths against path traversal.

        Ensures path containment within the permitted export directory using
        path-aware resolution (Path.resolve() and Path.is_relative_to()).
        Prevents traversal (..), sibling-directory prefix collisions, symlink escapes,
        and unauthorized writes to system directories.
        """
        if not filepath or not isinstance(filepath, str):
            raise ValueError(f"Invalid export filename: '{filepath}'")

        clean_path = filepath.strip()
        if not clean_path:
            raise ValueError(f"Invalid export filename: '{filepath}'")

        if allow_absolute is None:
            allow_absolute = self.allow_absolute

        # Normalize backslashes for cross-platform consistency
        normalized = clean_path.replace("\\", "/")

        # 1. Reject explicit '..' traversal before any resolution
        parts = normalized.split("/")
        if ".." in parts:
            raise ValueError(f"Path traversal detected in export path: '{filepath}'")

        # 2. Validate file extension against SUPPORTED_FORMATS
        ext = os.path.splitext(clean_path)[1].lower()
        if ext and ext not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported export format '{ext}'. Supported formats: {', '.join(self.SUPPORTED_FORMATS)}"
            )

        # 3. Resolve permitted base directory
        if not export_dir:
            export_dir = self.default_export_dir

        if not os.path.isabs(export_dir):
            base_project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            resolved_base = Path(base_project_dir) / export_dir
        else:
            resolved_base = Path(export_dir)

        base_dir_path = resolved_base.resolve()

        # 4. Check if clean_path is absolute or drive-anchored
        is_abs = (
            os.path.isabs(clean_path)
            or bool(re.match(r"^[a-zA-Z]:[/\\]", clean_path))
            or clean_path.startswith(("/", "\\"))
        )

        if is_abs:
            # Validate system directories early regardless of allow_absolute
            self._verify_not_prohibited_directory(Path(clean_path), filepath)

            if not allow_absolute:
                raise ValueError(f"Absolute export paths are not permitted: '{filepath}'")

            target_path = Path(clean_path)
            try:
                real_parent = target_path.parent.resolve()
                real_target = real_parent / target_path.name
            except (OSError, RuntimeError) as e:
                raise ValueError(f"Invalid export path: '{filepath}': {e}")

            # Check if target is inside base_dir_path
            if real_target.is_relative_to(base_dir_path):
                self.ensure_export_dir(str(real_parent))
                return str(real_target)

            # If an explicit export_dir was given (different from default), reject escaping it
            if export_dir != self.DEFAULT_EXPORT_DIR and export_dir != str(base_dir_path):
                raise ValueError(f"Export path '{filepath}' is outside permitted directory '{export_dir}'")

            # Check sibling directory prefix collisions against base_dir_path
            if (
                real_target.parent.parent == base_dir_path.parent
                and real_target.parent != base_dir_path
                and real_target.parent.name.startswith(base_dir_path.name)
            ):
                raise ValueError(f"Path traversal detected in export path: '{filepath}'")

            # Validate against system directories
            self._verify_not_prohibited_directory(real_target, filepath)
            self.ensure_export_dir(str(real_parent))
            return str(real_target)

        # 5. Relative path: resolve relative to base_dir_path
        filename = os.path.basename(normalized)
        if not filename or filename in (".", ".."):
            raise ValueError(f"Invalid export filename: '{filepath}'")

        # Resolve relative target against base_dir_path
        target_path = base_dir_path / normalized
        try:
            real_parent = target_path.parent.resolve()
            real_target = real_parent / target_path.name
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid export path: '{filepath}': {e}")

        # Path-aware containment check: replaces vulnerable string startswith!
        # Prevents sibling directory collisions (e.g. exports_evil vs exports)
        # and symlink escapes pointing outside base_dir_path
        if not real_target.is_relative_to(base_dir_path):
            raise ValueError(f"Path traversal detected in export path: '{filepath}'")

        self.ensure_export_dir(str(real_parent))
        return str(real_target)

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
        if wrpcap is None:
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
