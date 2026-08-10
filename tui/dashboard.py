import time
from typing import List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from storage.models import PacketInfo
from utils.privacy import PrivacyFilter
from utils.constants import APP_VERSION, format_bytes
from tui.helpers import (
    format_packet_row,
    protocol_badge,
    severity_badge,
    build_bar,
    format_elapsed,
    truncate,
)

console = Console()


class LiveDashboard:
    def __init__(
        self,
        stats_aggregator,
        alert_manager,
        privacy_filter: Optional[PrivacyFilter] = None,
    ):
        self.stats_aggregator = stats_aggregator
        self.alert_manager = alert_manager
        self.privacy_filter = privacy_filter
        self.start_time = time.time()

        self.layout = Layout()
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="alerts", size=8),
            Layout(name="footer", size=3),
        )

        self.layout["main"].split_row(
            Layout(name="left", ratio=6), Layout(name="right", ratio=4)
        )

        self.layout["right"].split_column(
            Layout(name="protocols", ratio=1),
            Layout(name="top_talkers", ratio=1),
        )

        self.packets_buffer = []

    def build_layout(self) -> Layout:
        return self.layout

    def update(
        self,
        packets_buffer: List[PacketInfo],
        dropped_count: int = 0,
        queue_depth: int = 0,
        queue_capacity: int = 5000,
        paused: bool = False,
        degraded_subsystems: Optional[dict] = None,
        avg_latency_ms: float = 0.0,
    ):
        self.packets_buffer = packets_buffer[-20:]  # Keep last 20 for table display

        # Header
        elapsed = format_elapsed(time.time() - self.start_time)
        pause_badge = " [bold yellow]⏸ PAUSED (CAPTURE CONTINUES)[/bold yellow]" if paused else ""
        header_text = Text.assemble(
            ("my-sentinel v", "bold cyan"),
            (APP_VERSION, "bold cyan"),
            " | ",
            ("Keybindings: [P]ause [F]ilter [E]xport [Q]uit", "white"),
            " | Elapsed: ",
            (elapsed, "bold green"),
        )
        if paused:
            header_text.append(" | ⏸ PAUSED — CAPTURE CONTINUES", style="bold yellow")

        self.layout["header"].update(Panel(header_text, style="white on blue"))

        # Left Panel (Packet Stream)
        pkt_table = Table(
            show_header=True, header_style="bold magenta", expand=True
        )
        pkt_table.add_column("#", width=5)
        pkt_table.add_column("Time", width=12)
        pkt_table.add_column("Source", width=20)
        pkt_table.add_column("Destination", width=20)
        pkt_table.add_column("Proto", width=6)
        pkt_table.add_column("Length", width=8, justify="right")
        pkt_table.add_column("Service", width=10)
        pkt_table.add_column("Info")

        for pkt in reversed(self.packets_buffer):
            row = format_packet_row(pkt, self.privacy_filter)
            pkt_table.add_row(*row)

        stream_title = "Packet Stream (Live)"
        if paused:
            stream_title = "Packet Stream (PAUSED — Capture Running)"
        self.layout["left"].update(
            Panel(pkt_table, title=stream_title)
        )

        # Right Top Panel (Protocol Distribution)
        proto_table = Table(show_header=True, expand=True, box=None)
        proto_table.add_column("Protocol")
        proto_table.add_column("Chart")
        proto_table.add_column("%", justify="right")

        stats = self.stats_aggregator.get_snapshot()
        proto_stats = stats.protocol_counts
        total_pkts = stats.total_packets

        if total_pkts > 0:
            for proto, count in sorted(
                proto_stats.items(), key=lambda x: x[1], reverse=True
            )[:5]:
                pct = (count / total_pkts) * 100
                proto_table.add_row(
                    protocol_badge(proto),
                    build_bar(count, total_pkts, 15),
                    f"{pct:.1f}%",
                )

        self.layout["protocols"].update(
            Panel(proto_table, title="Protocol Distribution")
        )

        # Right Bottom Panel (Top Talkers)
        talkers_table = Table(show_header=True, expand=True, box=None)
        talkers_table.add_column("IP")
        talkers_table.add_column("Packets")
        talkers_table.add_column("Bytes")
        talkers_table.add_column("Chart")

        top_ips = stats.top_talkers  # list of dicts [{'ip': ..., 'bytes': ..., 'packets': ...}]
        max_bytes = max([item["bytes"] for item in top_ips]) if top_ips else 0

        for item in top_ips:
            ip_raw = item["ip"]
            ip_str = (
                self.privacy_filter.ip(ip_raw)
                if self.privacy_filter and self.privacy_filter.enabled
                else ip_raw
            )
            talkers_table.add_row(
                ip_str,
                str(item["packets"]),
                format_bytes(item["bytes"]),
                build_bar(item["bytes"], max_bytes, 10),
            )

        self.layout["top_talkers"].update(Panel(talkers_table, title="Top Talkers"))

        # Alerts Panel
        alerts_table = Table(show_header=True, expand=True, box=None)
        alerts_table.add_column("Time", width=12)
        alerts_table.add_column("Severity", width=12)
        alerts_table.add_column("Message")

        recent_alerts = self.alert_manager.get_recent(n=5)
        for alert in recent_alerts:
            alerts_table.add_row(
                alert.timestamp_str or "",
                severity_badge(alert.severity),
                truncate(alert.message, 80),
            )

        alerts_title = "Threat Alerts Feed"
        if degraded_subsystems:
            degraded_str = ", ".join(f"{k}:{v}" for k, v in degraded_subsystems.items())
            alerts_title += f" [DEGRADED: {degraded_str}]"

        self.layout["alerts"].update(
            Panel(alerts_table, title=alerts_title, border_style="red")
        )

        # Calculate Queue Utilization and Health
        queue_util = (queue_depth / queue_capacity * 100) if queue_capacity > 0 else 0
        total_captured = stats.total_packets + dropped_count
        drop_rate = (dropped_count / total_captured * 100) if total_captured > 0 else 0

        if drop_rate > 10 or queue_util > 90:
            health_str = "[bold red]CRITICAL[/bold red]"
        elif drop_rate > 1 or queue_util > 70 or degraded_subsystems:
            health_str = "[bold yellow]DEGRADED[/bold yellow]"
        else:
            health_str = "[bold green]HEALTHY[/bold green]"

        # Footer Bar
        footer_text = (
            f"Pkts: [bold]{stats.total_packets:,}[/bold] | "
            f"Dropped: [bold {'red' if dropped_count > 0 else 'white'}]{dropped_count:,}[/bold] | "
            f"Queue: [bold]{queue_depth}/{queue_capacity}[/bold] ({queue_util:.0f}%) | "
            f"Health: {health_str} | "
            f"Rate: [bold]{stats.packets_per_sec:.1f} pps[/bold] | "
            f"Bytes: [bold]{format_bytes(stats.total_bytes)}[/bold] | "
            f"Lat: [bold]{avg_latency_ms:.1f}ms[/bold]"
        )
        self.layout["footer"].update(
            Panel(Text.from_markup(footer_text), style="black on green")
        )

    def get_renderable(self) -> Layout:
        return self.layout
