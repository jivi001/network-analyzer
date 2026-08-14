import time
from typing import List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.text import Text

from storage.models import PacketInfo, StatsSnapshot, AlertInfo
from utils.constants import format_bytes
from utils.console import console, ScreenState, screen_manager
from tui.helpers import protocol_badge, severity_badge, build_bar, format_elapsed


def display_pcap_loading(filepath: str):
    """Show progress while loading in TASK_RUNNING state."""
    screen_manager.set_state(ScreenState.TASK_RUNNING)
    console.print(f"[cyan]Loading and parsing PCAP file '{filepath}'...[/cyan]")


def display_pcap_analysis(
    packets: List[PacketInfo], stats: StatsSnapshot, alerts: List[AlertInfo]
):
    """Render full PCAP analysis results in TASK_COMPLETE state."""
    screen_manager.set_state(ScreenState.TASK_COMPLETE)

    # Summary panel
    summary_text = (
        f"Total Packets: [bold cyan]{stats.total_packets:,}[/bold cyan]\n"
        f"Total Bytes: [bold cyan]{format_bytes(stats.total_bytes)}[/bold cyan]\n"
        f"Average Packet Size: [bold yellow]{stats.avg_packet_size:.1f} B[/bold yellow]\n"
        f"Unique Hosts: [bold green]{stats.unique_hosts_total}[/bold green]\n"
        f"Captured Duration: [bold white]{format_elapsed(stats.elapsed_seconds)}[/bold white]"
    )
    console.print(
        Panel(
            Text.from_markup(summary_text),
            title="PCAP Forensic Summary",
            border_style="blue",
        )
    )
    console.print()

    # Protocol distribution table
    proto_table = Table(show_header=True, header_style="bold magenta", expand=True)
    proto_table.add_column("Protocol")
    proto_table.add_column("Count", justify="right")
    proto_table.add_column("Percentage", justify="right")
    proto_table.add_column("Distribution Bar")

    if stats.total_packets > 0:
        for proto, count in sorted(
            stats.protocol_counts.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / stats.total_packets) * 100
            proto_table.add_row(
                protocol_badge(proto),
                f"{count:,}",
                f"{pct:.1f}%",
                build_bar(count, stats.total_packets, 25),
            )
    console.print(Panel(proto_table, title="Protocol Breakdown"))

    # Top Talkers table
    if stats.top_talkers:
        talkers_table = Table(show_header=True, header_style="bold green", expand=True)
        talkers_table.add_column("IP Address")
        talkers_table.add_column("Bytes Volume", justify="right")
        talkers_table.add_column("Packet Count", justify="right")

        for item in stats.top_talkers:
            talkers_table.add_row(
                item["ip"],
                format_bytes(item["bytes"]),
                f"{item['packets']:,}",
            )
        console.print(Panel(talkers_table, title="Top Data Sources"))

    # Alerts Found table
    if alerts:
        alerts_table = Table(show_header=True, header_style="bold red", expand=True)
        alerts_table.add_column("Time", width=12)
        alerts_table.add_column("Severity", width=12)
        alerts_table.add_column("Rule Name")
        alerts_table.add_column("Message")

        for alert in alerts:
            alerts_table.add_row(
                alert.timestamp_str or "",
                severity_badge(alert.severity),
                alert.rule_name,
                alert.message,
            )
        console.print(Panel(alerts_table, title=f"Flagged Threats ({len(alerts)})", border_style="red"))
