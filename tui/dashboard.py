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
from utils.console import console
from tui.helpers import (
    format_packet_row,
    protocol_badge,
    severity_badge,
    build_bar,
    format_elapsed,
    truncate,
)


class LiveDashboard:
    def __init__(
        self,
        stats_aggregator,
        alert_manager,
        privacy_filter: Optional[PrivacyFilter] = None,
        dashboard_console: Optional[Console] = None,
        max_render_rows: int = 50,
    ):
        self.stats_aggregator = stats_aggregator
        self.alert_manager = alert_manager
        self.privacy_filter = privacy_filter
        self.console = dashboard_console or console
        self.max_render_rows = max(10, min(max_render_rows, 100))
        self.start_time = time.time()

        self.layout = Layout()
        self.packets_buffer = []
        self._last_height = 0
        self._last_width = 0

        # TUI Render Telemetry (Rolling EMA & Frame Counter)
        self.total_frames = 0
        self.last_render_ms = 0.0
        self.avg_render_ms = 0.0
        self.peak_render_ms = 0.0

        self._rebuild_layout_structure(
            self.console.height or self.console.size.height or 40,
            self.console.width or self.console.size.width or 120,
        )

    def _rebuild_layout_structure(self, term_height: int, term_width: int):
        """Dynamically allocate vertical and horizontal layout proportions based on terminal size."""
        self._last_height = term_height
        self._last_width = term_width

        # Determine alerts panel size dynamically: compact on small screens, expanded on tall screens
        if term_height < 30:
            alerts_size = 4
        elif term_height < 45:
            alerts_size = 5
        else:
            alerts_size = 6

        self.layout = Layout()
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="alerts", size=alerts_size),
            Layout(name="footer", size=3),
        )

        # Allocate 70% width to packet table on standard/wide terminals, 60% on smaller terminals
        left_ratio = 7 if term_width >= 110 else 6
        right_ratio = 3 if term_width >= 110 else 4

        self.layout["main"].split_row(
            Layout(name="left", ratio=left_ratio),
            Layout(name="right", ratio=right_ratio),
        )

        self.layout["right"].split_column(
            Layout(name="protocols", ratio=1),
            Layout(name="top_talkers", ratio=1),
        )

    def build_layout(self) -> Layout:
        return self.layout

    def calculate_visible_rows(self) -> int:
        """Calculate the maximum visible packet rows based on current terminal height."""
        term_height = self.console.height or self.console.size.height or 40
        if term_height < 30:
            alerts_size = 4
        elif term_height < 45:
            alerts_size = 5
        else:
            alerts_size = 6

        available_main_height = max(8, term_height - 3 - alerts_size - 3)
        usable_packet_rows = max(4, available_main_height - 4)
        return min(usable_packet_rows, self.max_render_rows)

    def update(
        self,
        packets_buffer: List[PacketInfo],
        captured_count: int = 0,
        enqueued_count: int = 0,
        processed_count: int = 0,
        dropped_count: int = 0,
        queue_depth: int = 0,
        queue_capacity: int = 10000,
        paused: bool = False,
        degraded_subsystems: Optional[dict] = None,
        avg_latency_ms: float = 0.0,
        processing_errors: int = 0,
        pcap_errors: int = 0,
        db_errors: int = 0,
        captured_pps: float = 0.0,
    ):
        t_start = time.perf_counter()
        term_height = self.console.height or self.console.size.height or 40
        term_width = self.console.width or self.console.size.width or 120

        # Re-structure layout if terminal resized
        if term_height != self._last_height or term_width != self._last_width:
            self._rebuild_layout_structure(term_height, term_width)

        # Calculate exact visible packet rows from available main panel height
        visible_rows = self.calculate_visible_rows()

        # Snapshot-based slicing of the latest packets only
        self.packets_buffer = packets_buffer[-visible_rows:] if packets_buffer else []

        # Header
        elapsed = format_elapsed(time.time() - self.start_time)
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

        # Left Panel (Packet Stream) — Dynamic width and bounded expansion
        pkt_table = Table(
            show_header=True,
            header_style="bold magenta",
            expand=True,
            show_edge=False,
            pad_edge=False,
        )
        pkt_table.add_column("#", width=6, no_wrap=True, justify="right")
        pkt_table.add_column("Time", width=12, no_wrap=True)
        pkt_table.add_column("Source", ratio=2, min_width=16, no_wrap=True)
        pkt_table.add_column("Destination", ratio=2, min_width=16, no_wrap=True)
        pkt_table.add_column("Proto", width=6, no_wrap=True)
        pkt_table.add_column("Length", width=7, justify="right", no_wrap=True)
        pkt_table.add_column("Service", width=9, no_wrap=True)
        pkt_table.add_column("Info", ratio=3, overflow="ellipsis", no_wrap=True)

        if not self.packets_buffer:
            pkt_table.add_row("-", "-", "-", "[dim yellow]Waiting for live traffic...[/dim yellow]", "-", "-", "-", "-")
        else:
            for pkt in reversed(self.packets_buffer):
                row = format_packet_row(pkt, self.privacy_filter)
                pkt_table.add_row(*row)

        stream_title = f"Packet Stream (Live — Showing Latest {len(self.packets_buffer)})"
        if paused:
            stream_title = f"Packet Stream (PAUSED — Latest {len(self.packets_buffer)} Shown)"
        self.layout["left"].update(
            Panel(pkt_table, title=stream_title)
        )

        # Right Top Panel (Protocol Distribution)
        stats = self.stats_aggregator.get_snapshot()
        proto_stats = stats.protocol_counts
        total_pkts = stats.total_packets

        if total_pkts > 0:
            proto_table = Table(show_header=True, expand=True, box=None)
            proto_table.add_column("Protocol")
            proto_table.add_column("Chart")
            proto_table.add_column("%", justify="right")
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
        else:
            from rich.align import Align
            self.layout["protocols"].update(
                Panel(Align.center(Text("No traffic data", style="dim yellow")), title="Protocol Distribution")
            )

        # Right Bottom Panel (Top Talkers)
        top_ips = stats.top_talkers  # list of dicts [{'ip': ..., 'bytes': ..., 'packets': ...}]
        if top_ips:
            talkers_table = Table(show_header=True, expand=True, box=None)
            talkers_table.add_column("IP")
            talkers_table.add_column("Packets")
            talkers_table.add_column("Bytes")
            talkers_table.add_column("Chart")
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
        else:
            from rich.align import Align
            self.layout["top_talkers"].update(
                Panel(Align.center(Text("No traffic observed", style="dim yellow")), title="Top Talkers")
            )

        # Alerts Panel
        from rich.markup import escape
        recent_alerts = self.alert_manager.get_recent(n=5)

        alerts_title = "Threat Alerts Feed"
        if degraded_subsystems:
            degraded_str = ", ".join(f"{k}:{v}" for k, v in degraded_subsystems.items())
            alerts_title += f" [DEGRADED: {escape(degraded_str)}]"

        if recent_alerts:
            alerts_table = Table(show_header=True, expand=True, box=None)
            alerts_table.add_column("Time", width=12)
            alerts_table.add_column("Severity", width=12)
            alerts_table.add_column("Message")
            for alert in recent_alerts:
                alerts_table.add_row(
                    alert.timestamp_str or "",
                    severity_badge(alert.severity),
                    escape(truncate(alert.message, 80)),
                )
            self.layout["alerts"].update(
                Panel(alerts_table, title=alerts_title, border_style="red")
            )
        else:
            from rich.align import Align
            self.layout["alerts"].update(
                Panel(Align.center(Text("No security alerts detected", style="dim green")), title=alerts_title, border_style="green")
            )

        # Calculate Queue Utilization and System Health
        queue_util = (queue_depth / queue_capacity * 100) if queue_capacity > 0 else 0
        total_lost = dropped_count + processing_errors
        total_received = captured_count if captured_count > 0 else (stats.total_packets + total_lost)
        drop_rate = (total_lost / total_received * 100) if total_received > 0 else 0

        if drop_rate > 10 or queue_util > 90:
            health_str = "[bold red]CRITICAL[/bold red]"
        elif drop_rate > 1 or queue_util > 70 or degraded_subsystems or pcap_errors > 0 or db_errors > 0:
            health_str = "[bold yellow]DEGRADED[/bold yellow]"
        else:
            health_str = "[bold green]HEALTHY[/bold green]"

        # Footer Bar with honest metrics breakdown
        drop_style = "bold red" if dropped_count > 0 else "bold white"
        rate_val = captured_pps if captured_pps > 0 else stats.packets_per_sec
        footer_text = (
            f"Cap: [bold]{captured_count:,}[/bold] | "
            f"Proc: [bold]{processed_count:,}[/bold] | "
            f"Dropped: [{drop_style}]{dropped_count:,}[/{drop_style}] | "
            f"Queue: [bold]{queue_depth:,}/{queue_capacity:,}[/bold] ({queue_util:.1f}%) | "
            f"Health: {health_str} | "
            f"Rate: [bold]{rate_val:.1f} pps[/bold] | "
            f"Bytes: [bold]{format_bytes(stats.total_bytes)}[/bold] | "
            f"Lat: [bold]{avg_latency_ms:.1f}ms[/bold]"
        )
        self.layout["footer"].update(
            Panel(Text.from_markup(footer_text), style="black on green")
        )

        # Record TUI render telemetry (EMA duration & peak)
        t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        self.last_render_ms = t_elapsed_ms
        self.total_frames += 1
        if self.total_frames == 1:
            self.avg_render_ms = t_elapsed_ms
            self.peak_render_ms = t_elapsed_ms
        else:
            self.avg_render_ms = (self.avg_render_ms * 0.9) + (t_elapsed_ms * 0.1)
            if t_elapsed_ms > self.peak_render_ms:
                self.peak_render_ms = t_elapsed_ms

    def get_renderable(self) -> Layout:
        return self.layout