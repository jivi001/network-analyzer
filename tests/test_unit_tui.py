"""
test_unit_tui.py — Comprehensive unit tests for TUI views and helper formatters.
"""

from rich.console import Console
import pytest

from storage.models import PacketInfo, AlertInfo, HostInfo, SessionInfo
from core.stats import StatsAggregator
from detection.alerts import AlertManager
from tui.helpers import (
    format_packet_row,
    format_alert_row,
    format_host_row,
    protocol_badge,
    severity_badge,
    build_bar,
    truncate,
    format_elapsed,
)
from tui.dashboard import LiveDashboard
from tui.history_view import (
    display_sessions,
    display_alerts_history,
    display_hosts_table,
    display_session_detail,
)


class TestTuiHelpers:
    def test_format_packet_row(self):
        pkt = PacketInfo(id=1, timestamp=100.0, src_ip="192.168.1.10", src_port=54321, dst_ip="192.168.1.1", dst_port=80, protocol="TCP", length=128, service="HTTP", info="GET /")
        row = format_packet_row(pkt)
        assert len(row) == 8
        assert "192.168.1.10:54321" in row[2]
        assert "192.168.1.1:80" in row[3]

    def test_format_alert_row(self):
        alert = AlertInfo(rule_name="SYN Probe", severity="HIGH", message="Probe detected", src_ip="1.1.1.1", dst_ip="2.2.2.2", timestamp_str="10:00:00")
        row = format_alert_row(alert)
        assert len(row) == 6
        assert "SYN Probe" in row[2]

    def test_format_host_row(self):
        host = HostInfo(ip_address="10.0.0.1", mac_address="00:11:22:33:44:55", hostname="gateway", open_ports=[80, 443])
        row = format_host_row(host)
        assert len(row) == 8
        assert "10.0.0.1" in row[0]
        assert "gateway" in row[2]
        assert "2" in row[3]

    def test_build_bar_and_formatting(self):
        bar = build_bar(50, 100, width=10)
        assert len(bar) == 10
        assert "=" in bar or "-" in bar

        assert truncate("short text", 20) == "short text"
        assert truncate("a very long string that exceeds limit", 10) == "a very ..."
        assert format_elapsed(3665) == "1:01:05"


class TestLiveDashboard:
    def test_dashboard_renderable_creation(self):
        stats_agg = StatsAggregator()
        alert_mgr = AlertManager()
        dash = LiveDashboard(stats_agg, alert_mgr)

        pkt = PacketInfo(id=1, src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP", length=64)
        stats_agg.update(pkt)
        dash.update([pkt], queue_depth=1, queue_capacity=100, captured_count=1, processed_count=1)

        renderable = dash.get_renderable()
        assert renderable is not None


class TestHistoryViews:
    def test_display_sessions(self):
        sessions = [
            SessionInfo(id=1, session_type="live_capture", start_time="10:00:00", end_time="10:05:00", packet_count=100, total_bytes=5000, alert_count=1, status="completed")
        ]
        display_sessions(sessions)

    def test_display_alerts_history(self):
        alerts = [
            AlertInfo(rule_name="R1", severity="HIGH", message="Alert 1", timestamp_str="10:00:00")
        ]
        display_alerts_history(alerts)

    def test_display_hosts_table(self):
        hosts = [
            HostInfo(ip_address="192.168.1.1", hostname="router", open_ports=[80])
        ]
        display_hosts_table(hosts)

    def test_display_session_detail(self):
        session = SessionInfo(id=1, session_type="offline_pcap", target="test.pcap", packet_count=50, total_bytes=2000, alert_count=0, status="completed")
        display_session_detail(session, [])
