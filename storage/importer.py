"""
importer.py — Strict, schema-aware, transaction-safe JSON data importer for SQLite database.
"""

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from storage.database import Database
from storage.models import SessionInfo, AlertInfo, HostInfo, StatsSnapshot
from utils.path_helpers import resolve_path

logger = logging.getLogger(__name__)


@dataclass
class ImportResult:
    """Detailed summary of an executed JSON import operation."""
    success: bool
    session_id: int = 0
    total_records: int = 0
    alert_count: int = 0
    host_count: int = 0
    packet_count: int = 0
    total_bytes: int = 0
    message: str = ""

    def __bool__(self) -> bool:
        return self.success


class Importer:
    """Import Manager for importing exported JSON records back into the SQLite database."""

    def __init__(self, db: Database):
        self.db = db

    def _truncate_str(self, val: Any, max_len: int = 500) -> str:
        if not isinstance(val, str):
            return str(val or "")[:max_len]
        return val[:max_len]

    def _safe_int(self, val: Any, default: int = 0) -> int:
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _safe_float(self, val: Any, default: float = 0.0) -> float:
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    def validate_json_schema(self, data: Any) -> Tuple[bool, str]:
        """
        Validates whether parsed JSON conforms to the My-Sentinel export format schema.
        Accepts full exports, alert exports, session summaries, or host records.
        """
        if not isinstance(data, dict):
            return False, "Root JSON element must be an object/dictionary."

        recognized_sections = {"metadata", "stats", "alerts", "hosts", "packets", "session"}
        present_sections = set(data.keys()) & recognized_sections

        if not present_sections:
            return (
                False,
                "JSON structure is not compatible with My-Sentinel import format. "
                "Expected at least one of: metadata, stats, alerts, hosts, packets.",
            )

        if "alerts" in data and not isinstance(data["alerts"], list):
            return False, "'alerts' section must be an array/list."

        if "hosts" in data and not isinstance(data["hosts"], list):
            return False, "'hosts' section must be an array/list."

        if "stats" in data and not isinstance(data["stats"], dict):
            return False, "'stats' section must be an object/dictionary."

        if "metadata" in data and not isinstance(data["metadata"], dict):
            return False, "'metadata' section must be an object/dictionary."

        return True, ""

    def import_json(self, filepath: str, raise_on_error: bool = False) -> ImportResult:
        """
        Validates, parses, and imports a JSON export file into SQLite with transaction safety.
        Returns an ImportResult object (evaluating to True/False in boolean checks).
        """
        try:
            target_path = resolve_path(filepath)
            if not target_path:
                raise ValueError(f"Invalid file path: '{filepath}'")

            if not target_path.exists():
                raise FileNotFoundError(f"JSON file not found: '{target_path}'")

            if target_path.is_dir():
                raise IsADirectoryError(f"The selected path is a directory, not a file: '{target_path}'")

            if target_path.suffix.lower() != ".json":
                raise ValueError(f"Unsupported import file type '{target_path.suffix}'. Expected .json")

            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON format. The file could not be parsed: {e.msg} (line {e.lineno})")
            except PermissionError as e:
                raise PermissionError(f"Permission denied while reading JSON file: {e}")
            except Exception as e:
                raise RuntimeError(f"Error reading JSON file: {e}")

            # Schema validation
            is_valid, schema_err = self.validate_json_schema(data)
            if not is_valid:
                raise ValueError(schema_err)

            alerts_data = data.get("alerts", [])
            if not isinstance(alerts_data, list):
                alerts_data = []

            stats_data = data.get("stats", {})
            if not isinstance(stats_data, dict):
                stats_data = {}

            hosts_data = data.get("hosts", [])
            if not isinstance(hosts_data, list):
                hosts_data = []

            packets_data = data.get("packets", [])
            if not isinstance(packets_data, list):
                packets_data = []

            metadata = data.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            total_packet_count = self._safe_int(
                stats_data.get("total_packets") or metadata.get("total_packets") or len(packets_data), 0
            )
            total_byte_count = self._safe_int(stats_data.get("total_bytes", 0))
            export_time = (
                metadata.get("exported_at")
                or metadata.get("timestamp")
                or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )

            # Construct Session Info
            session = SessionInfo(
                session_type="imported",
                start_time=self._truncate_str(export_time, 100),
                end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                status="completed",
                target=self._truncate_str(target_path.name, 250),
                alert_count=len(alerts_data),
                packet_count=total_packet_count,
                total_bytes=total_byte_count,
            )

            # Parse alerts into models
            alerts_to_save: List[AlertInfo] = []
            for a_dict in alerts_data:
                if not isinstance(a_dict, dict):
                    continue
                alert = AlertInfo(
                    timestamp_str=self._truncate_str(a_dict.get("timestamp", a_dict.get("timestamp_str", "")), 100),
                    severity=self._truncate_str(a_dict.get("severity", "INFO"), 20).upper(),
                    rule_name=self._truncate_str(a_dict.get("rule_name", "Imported Alert"), 200),
                    message=self._truncate_str(a_dict.get("message", ""), 1000),
                    src_ip=self._truncate_str(a_dict.get("src_ip", ""), 45),
                    dst_ip=self._truncate_str(a_dict.get("dst_ip", ""), 45),
                    dst_port=self._safe_int(a_dict.get("dst_port", 0)),
                    protocol=self._truncate_str(a_dict.get("protocol", ""), 20),
                )
                alerts_to_save.append(alert)

            # Parse hosts into models
            hosts_to_save: List[HostInfo] = []
            for h_dict in hosts_data:
                if not isinstance(h_dict, dict):
                    continue
                ip_addr = self._truncate_str(h_dict.get("ip_address", h_dict.get("ip", "")), 45)
                if not ip_addr:
                    continue
                host = HostInfo(
                    ip_address=ip_addr,
                    mac_address=self._truncate_str(h_dict.get("mac_address", ""), 45),
                    hostname=self._truncate_str(h_dict.get("hostname", ""), 250),
                    open_ports=h_dict.get("open_ports", []) if isinstance(h_dict.get("open_ports"), list) else [],
                    services=h_dict.get("services", {}) if isinstance(h_dict.get("services"), dict) else {},
                    os_guess=self._truncate_str(h_dict.get("os_guess", ""), 200),
                    first_seen=self._truncate_str(h_dict.get("first_seen", ""), 100),
                    last_seen=self._truncate_str(h_dict.get("last_seen", ""), 100),
                    source=self._truncate_str(h_dict.get("source", "imported"), 50),
                    packet_count=self._safe_int(h_dict.get("packet_count", 0)),
                    byte_count=self._safe_int(h_dict.get("byte_count", 0)),
                    state=self._truncate_str(h_dict.get("state", "up"), 20),
                )
                hosts_to_save.append(host)

            # Transaction execution block
            with self.db.lock:
                session_id = self.db.create_session(session)

                # Save stats snapshot if present
                if stats_data:
                    stats_snapshot = StatsSnapshot(
                        total_packets=total_packet_count,
                        total_bytes=total_byte_count,
                        unique_hosts_total=self._safe_int(stats_data.get("unique_hosts", len(hosts_to_save))),
                        protocol_counts=stats_data.get("protocol_counts", {}) if isinstance(stats_data.get("protocol_counts"), dict) else {},
                        top_talkers=stats_data.get("top_talkers", []) if isinstance(stats_data.get("top_talkers"), list) else [],
                        packets_per_sec=self._safe_float(stats_data.get("packets_per_sec", 0.0)),
                        bytes_per_sec=self._safe_float(stats_data.get("bytes_per_sec", 0.0)),
                        elapsed_seconds=self._safe_float(stats_data.get("elapsed_seconds", 0.0)),
                    )
                    self.db.save_packet_summary(session_id, stats_snapshot)

                # Save alerts referencing session_id
                if alerts_to_save:
                    for a in alerts_to_save:
                        a.session_id = session_id
                    self.db.save_alerts_batch(alerts_to_save)

                # Save hosts
                if hosts_to_save:
                    for h in hosts_to_save:
                        self.db.save_host(h)

            total_imported = len(alerts_to_save) + len(hosts_to_save) + (1 if stats_data else 0)
            return ImportResult(
                success=True,
                session_id=session_id,
                total_records=total_imported,
                alert_count=len(alerts_to_save),
                host_count=len(hosts_to_save),
                packet_count=total_packet_count,
                total_bytes=total_byte_count,
                message=f"Successfully imported session #{session_id} from {target_path.name}",
            )
        except Exception as e:
            logger.error(f"Failed to import JSON file '{filepath}': {e}")
            if raise_on_error:
                raise
            return ImportResult(success=False, message=str(e))
