import json
import logging
import os
from datetime import datetime
from typing import Optional

from storage.database import Database
from storage.models import SessionInfo, AlertInfo, HostInfo, StatsSnapshot

logger = logging.getLogger(__name__)


class Importer:
    """Import Manager for importing exported JSON records back into the SQLite database."""

    def __init__(self, db: Database):
        self.db = db

    def _truncate_str(self, val: str, max_len: int = 500) -> str:
        if not isinstance(val, str):
            return str(val or "")[:max_len]
        return val[:max_len]

    def _safe_int(self, val, default: int = 0) -> int:
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def import_json(self, filepath: str) -> bool:
        """
        Reads a JSON export file and imports it into the database as a new session.
        Returns True if successful, False otherwise.
        """
        if not os.path.exists(filepath):
            logger.error(f"File '{filepath}' does not exist.")
            return False

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                logger.error("JSON payload is not a dictionary.")
                return False
        except Exception as e:
            logger.error(f"Error reading JSON file: {e}")
            return False

        alerts_data = data.get("alerts", [])
        if not isinstance(alerts_data, list):
            alerts_data = []

        stats_data = data.get("stats", {})
        if not isinstance(stats_data, dict):
            stats_data = {}

        hosts_data = data.get("hosts", [])
        if not isinstance(hosts_data, list):
            hosts_data = []

        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        # Create a new session for the imported data
        session = SessionInfo(
            session_type="imported",
            start_time=self._truncate_str(metadata.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")), 100),
            end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status="completed",
            target=self._truncate_str(os.path.basename(filepath), 250),
            alert_count=len(alerts_data),
            packet_count=self._safe_int(stats_data.get("total_packets", 0)),
            total_bytes=self._safe_int(stats_data.get("total_bytes", 0)),
        )

        try:
            # Transaction block
            with self.db.lock:
                session_id = self.db.create_session(session)

                # Import Stats
                if stats_data:
                    stats_snapshot = StatsSnapshot(
                        total_packets=self._safe_int(stats_data.get("total_packets", 0)),
                        total_bytes=self._safe_int(stats_data.get("total_bytes", 0)),
                        unique_hosts_total=self._safe_int(stats_data.get("unique_hosts", 0)),
                        protocol_counts=stats_data.get("protocol_counts", {}) if isinstance(stats_data.get("protocol_counts"), dict) else {},
                        top_talkers=stats_data.get("top_talkers", []) if isinstance(stats_data.get("top_talkers"), list) else [],
                    )
                    self.db.save_packet_summary(session_id, stats_snapshot)

                # Import Alerts
                if alerts_data:
                    alerts_to_save = []
                    for a_dict in alerts_data:
                        if not isinstance(a_dict, dict):
                            continue
                        alert = AlertInfo(
                            session_id=session_id,
                            timestamp_str=self._truncate_str(a_dict.get("timestamp", ""), 100),
                            severity=self._truncate_str(a_dict.get("severity", "INFO"), 20).upper(),
                            rule_name=self._truncate_str(a_dict.get("rule_name", ""), 200),
                            message=self._truncate_str(a_dict.get("message", ""), 1000),
                            src_ip=self._truncate_str(a_dict.get("src_ip", ""), 45),
                            dst_ip=self._truncate_str(a_dict.get("dst_ip", ""), 45),
                            dst_port=self._safe_int(a_dict.get("dst_port", 0)),
                            protocol=self._truncate_str(a_dict.get("protocol", ""), 20),
                        )
                        alerts_to_save.append(alert)
                    self.db.save_alerts_batch(alerts_to_save)

                # Import Hosts
                if hosts_data:
                    for h_dict in hosts_data:
                        if not isinstance(h_dict, dict):
                            continue
                        host = HostInfo(
                            ip_address=self._truncate_str(h_dict.get("ip_address", ""), 45),
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
                        if host.ip_address:
                            self.db.save_host(host)

            return True
        except Exception as e:
            logger.error(f"Failed to import JSON record: {e}")
            return False
