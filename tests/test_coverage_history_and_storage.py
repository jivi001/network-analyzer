"""
test_coverage_history_and_storage.py — Behavioral and branch coverage tests for tui/history_view.py and storage/exporter.py:
History sub-menu rendering, session/alert/host tables, detail views, and exporter/importer edge cases.
"""

import os
import tempfile
from unittest.mock import patch, MagicMock
import pytest

from storage.models import SessionInfo, AlertInfo, HostInfo, PacketInfo, StatsSnapshot
from storage.exporter import Exporter
from storage.importer import Importer
from storage.database import Database
from tui.history_view import (
    display_history_menu,
    display_sessions,
    display_alerts_history,
    display_hosts_table,
    display_session_detail,
)


class TestHistoryViewAndStorageCoverage:
    def test_display_history_menu_choices(self):
        for opt in ["1", "2", "3", "4", "5", "6"]:
            with patch("rich.prompt.Prompt.ask", return_value=opt):
                assert display_history_menu() == opt

    def test_display_sessions_empty_and_populated(self):
        # 1. Empty sessions
        display_sessions([])

        # 2. Populated sessions
        sessions = [
            SessionInfo(id=1, session_type="live_capture", start_time="2026-08-16 10:00:00", end_time="2026-08-16 10:05:00", packet_count=1500, total_bytes=1048576, alert_count=2, status="completed"),
            SessionInfo(id=2, session_type="nmap_scan", start_time="2026-08-16 10:10:00", packet_count=0, total_bytes=0, alert_count=0, status="completed"),
        ]
        display_sessions(sessions)

    def test_display_alerts_history_empty_and_populated(self):
        # 1. Empty alerts
        display_alerts_history([])

        # 2. Populated alerts
        alerts = [
            AlertInfo(timestamp_str="10:00:01", severity="CRITICAL", rule_name="DNS Exfil", src_ip="192.168.1.50", dst_ip="8.8.8.8", message="High entropy query"),
            AlertInfo(timestamp_str="10:00:02", severity="HIGH", rule_name="SYN Probe", src_ip="10.0.0.1", dst_ip="10.0.0.2", message="Probe detected"),
        ]
        display_alerts_history(alerts)

    def test_display_hosts_table_empty_and_populated(self):
        # 1. Empty hosts
        display_hosts_table([])

        # 2. Populated hosts with various attributes
        hosts = [
            HostInfo(ip_address="192.168.1.1", mac_address="00:11:22:33:44:55", hostname="gateway", open_ports=[80, 443], services={"80/tcp": "http", "443/tcp": "https"}, os_guess="Linux"),
            HostInfo(ip_address="192.168.1.50", mac_address="00:11:22:33:44:aa", hostname="", open_ports=[], services={}, os_guess=""),
        ]
        display_hosts_table(hosts)

    def test_display_session_detail_complete(self):
        session = SessionInfo(
            id=10,
            session_type="live_capture",
            interface="Ethernet",
            filter_applied="tcp port 80",
            start_time="2026-08-16 10:00:00",
            end_time="2026-08-16 10:05:00",
            packet_count=500,
            total_bytes=35000,
            alert_count=1,
            status="completed",
        )
        alerts = [
            AlertInfo(timestamp_str="10:02:00", severity="WARNING", rule_name="Port Scan", message="Touched ports"),
        ]
        display_session_detail(session, alerts)

    def test_exporter_json_with_payload_and_empty_csv(self):
        exporter = Exporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, "payload_export.json")
            csv_file = os.path.join(tmpdir, "empty_export.csv")

            # Export JSON with packets
            pkts = [PacketInfo(id=1, src_ip="1.1.1.1", dst_ip="2.2.2.2", length=64, protocol="TCP")]
            stats = StatsSnapshot(total_packets=1, total_bytes=64)
            exporter.export_json(json_file, stats=stats, packets=pkts)
            assert os.path.exists(json_file)

            # Export empty CSV
            exporter.export_csv(csv_file, packets=[], alerts=[])
            assert os.path.exists(csv_file)
