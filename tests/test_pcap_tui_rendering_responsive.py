import io
import pytest
from rich.console import Console
from storage.models import StatsSnapshot, AlertInfo, PacketInfo
from tui.pcap_view import render_pcap_forensic_dashboard, display_pcap_analysis


@pytest.fixture
def sample_forensic_data():
    stats = StatsSnapshot(
        total_packets=3784,
        total_bytes=3347834,
        elapsed_seconds=11.34,
        packets_per_sec=333.7,
        bytes_per_sec=295223.5,
        avg_packet_size=884.7,
        unique_hosts_total=18,
        protocol_counts={
            "TCP": 3120,
            "UDP": 450,
            "DNS": 180,
            "ICMP": 20,
            "ARP": 14,
            "IPv6": 8,
            "Other": 2,
        },
        top_talkers=[
            {"ip": f"192.168.1.{i}", "bytes": 1000000 - i * 50000, "packets": 1000 - i * 50}
            for i in range(1, 15)
        ],
        top_conversations=[
            {
                "src": f"192.168.1.{i}",
                "dst": f"10.0.0.{i}",
                "packets": 500 - i * 20,
            }
            for i in range(1, 20)
        ],
    )

    alerts = [
        AlertInfo(
            rule_name="DNS Exfiltration Tunnel",
            severity="CRITICAL",
            message="High entropy subdomain: 76616c69642e61747461636b2e6578616d706c65.attacker.com (entropy=4.21 bits/char)",
            timestamp_str="2026-08-16 10:00:01",
        ),
        AlertInfo(
            rule_name="Port Scan Detected",
            severity="WARNING",
            message="Host 192.168.1.50 scanned 35 target ports in 10-second window",
            timestamp_str="2026-08-16 10:00:02",
        ),
        AlertInfo(
            rule_name="ARP Spoofing Detected",
            severity="HIGH",
            message="IP 192.168.1.1 MAC mapping changed from 00:11:22:33:44:55 to aa:bb:cc:dd:ee:ff",
            timestamp_str="2026-08-16 10:00:03",
        ),
    ]

    return stats, alerts


class TestPcapTuiRenderingResponsive:
    """Test suite for terminal-responsive PCAP forensic dashboard rendering."""

    @pytest.mark.parametrize(
        "width,height",
        [
            (80, 24),   # Standard small terminal
            (100, 30),  # Default PowerShell / bash window
            (120, 40),  # Medium / standard desktop terminal
            (160, 50),  # Large widescreen terminal
            (70, 20),   # Extra-compact viewport
        ],
    )
    def test_rendering_across_terminal_dimensions(self, sample_forensic_data, width, height):
        stats, alerts = sample_forensic_data
        output = io.StringIO()
        test_console = Console(file=output, width=width, height=height, color_system="truecolor")

        dashboard = render_pcap_forensic_dashboard(stats, alerts, console_inst=test_console)
        test_console.print(dashboard)

        rendered_text = output.getvalue()
        assert "PCAP Forensic Summary" in rendered_text
        assert "Protocol Breakdown" in rendered_text
        assert "Top Conversations" in rendered_text
        assert "Top Data Sources" in rendered_text
        assert "Flagged Threats" in rendered_text
        assert "3,784" in rendered_text

    def test_rendering_zero_threats(self, sample_forensic_data):
        stats, _ = sample_forensic_data
        output = io.StringIO()
        test_console = Console(file=output, width=100, height=30)

        dashboard = render_pcap_forensic_dashboard(stats, [], console_inst=test_console)
        test_console.print(dashboard)

        rendered_text = output.getvalue()
        assert "No security threats detected" in rendered_text

    def test_rendering_many_threats_and_long_messages(self, sample_forensic_data):
        stats, _ = sample_forensic_data
        many_alerts = [
            AlertInfo(
                rule_name=f"Threat Rule {i}",
                severity="HIGH" if i % 2 == 0 else "CRITICAL",
                message=f"Long detailed threat diagnostic context with deep packet inspection payload hex values 0x{i:04x} and target URI parameters " * 2,
                timestamp_str="2026-08-16 10:15:30",
            )
            for i in range(1, 25)
        ]

        output = io.StringIO()
        test_console = Console(file=output, width=100, height=30)

        dashboard = render_pcap_forensic_dashboard(stats, many_alerts, console_inst=test_console)
        test_console.print(dashboard)

        rendered_text = output.getvalue()
        assert "Flagged Threats (24)" in rendered_text
        assert "more threats" in rendered_text

    def test_display_pcap_analysis_execution(self, sample_forensic_data):
        stats, alerts = sample_forensic_data
        packets = [PacketInfo(id=1, timestamp=100.0, length=64)]
        output = io.StringIO()
        test_console = Console(file=output, width=100, height=30)

        display_pcap_analysis(packets, stats, alerts, console_inst=test_console)
        rendered_text = output.getvalue()
        assert "PCAP Forensic Summary" in rendered_text
