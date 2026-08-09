import json
import os
from datetime import datetime
from typing import Optional

from storage.database import Database
from storage.models import SessionInfo, AlertInfo, HostInfo, StatsSnapshot

class Importer:
    """Import Manager for importing exported JSON records back into the SQLite database."""

    def __init__(self, db: Database):
        self.db = db

    def import_json(self, filepath: str) -> bool:
        """
        Reads a JSON export file and imports it into the database as a new session.
        Returns True if successful, False otherwise.
        """
        if not os.path.exists(filepath):
            print(f"Error: File '{filepath}' does not exist.")
            return False

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading JSON file: {e}")
            return False

        # Create a new session for the imported data
        session = SessionInfo(
            session_type="imported",
            start_time=data.get("metadata", {}).get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status="completed",
            target=os.path.basename(filepath)
        )
        
        alerts_data = data.get("alerts", [])
        stats_data = data.get("stats", {})
        hosts_data = data.get("hosts", [])

        # Update session with packet counts and alert counts from imported data
        session.alert_count = len(alerts_data)
        if stats_data:
            session.packet_count = stats_data.get("total_packets", 0)
            session.total_bytes = stats_data.get("total_bytes", 0)

        # Save session to DB
        session_id = self.db.create_session(session)

        # Import Stats
        if stats_data:
            stats_snapshot = StatsSnapshot(
                total_packets=stats_data.get("total_packets", 0),
                total_bytes=stats_data.get("total_bytes", 0),
                unique_hosts_total=stats_data.get("unique_hosts", 0),
                protocol_counts=stats_data.get("protocol_counts", {}),
                top_talkers=stats_data.get("top_talkers", [])
            )
            self.db.save_packet_summary(session_id, stats_snapshot)

        # Import Alerts
        if alerts_data:
            alerts_to_save = []
            for a_dict in alerts_data:
                alert = AlertInfo(
                    session_id=session_id,
                    timestamp_str=a_dict.get("timestamp", ""),
                    severity=a_dict.get("severity", "INFO"),
                    rule_name=a_dict.get("rule_name", ""),
                    message=a_dict.get("message", ""),
                    src_ip=a_dict.get("src_ip", ""),
                    dst_ip=a_dict.get("dst_ip", ""),
                    dst_port=a_dict.get("dst_port", 0),
                    protocol=a_dict.get("protocol", "")
                )
                alerts_to_save.append(alert)
            self.db.save_alerts_batch(alerts_to_save)

        # Import Hosts
        if hosts_data:
            for h_dict in hosts_data:
                host = HostInfo(
                    ip_address=h_dict.get("ip_address", ""),
                    mac_address=h_dict.get("mac_address", ""),
                    hostname=h_dict.get("hostname", ""),
                    open_ports=h_dict.get("open_ports", []),
                    services=h_dict.get("services", {}),
                    os_guess=h_dict.get("os_guess", ""),
                    first_seen=h_dict.get("first_seen", ""),
                    last_seen=h_dict.get("last_seen", ""),
                    source=h_dict.get("source", "imported"),
                    packet_count=h_dict.get("packet_count", 0),
                    byte_count=h_dict.get("byte_count", 0),
                    state=h_dict.get("state", "up")
                )
                self.db.save_host(host)

        return True
