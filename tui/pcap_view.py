"""
pcap_view.py — Responsive, terminal-adaptive Rich forensic dashboard for PCAP analysis.
"""

from typing import List, Optional
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from storage.models import PacketInfo, StatsSnapshot, AlertInfo
from utils.constants import format_bytes
from utils.console import console, ScreenState, screen_manager
from tui.helpers import protocol_badge, severity_badge, build_bar, format_elapsed


def display_pcap_loading(filepath: str, console_inst: Optional[Console] = None):
    """Show progress while loading in TASK_RUNNING state."""
    c = console_inst or console
    screen_manager.set_state(ScreenState.TASK_RUNNING)
    c.print(f"[cyan]📂 Loading and parsing PCAP file '[bold white]{filepath}[/bold white]'...[/cyan]")


def render_pcap_forensic_dashboard(
    stats: StatsSnapshot,
    alerts: List[AlertInfo],
    console_inst: Optional[Console] = None,
) -> Group:
    """
    Constructs a terminal-responsive, bounded forensic dashboard renderable Group.
    Adapts row limits, column wrapping, and side-by-side grid layouts based on terminal width and height.
    """
    c = console_inst or console
    term_width = c.width or c.size.width or 100
    term_height = c.height or c.size.height or 30

    # Determine responsive row limits based on terminal height
    if term_height <= 26:
        max_proto_rows = 4
        max_conv_rows = 3
        max_talker_rows = 3
        max_threat_rows = 3
        bar_width = 10
    elif term_height <= 36:
        max_proto_rows = 5
        max_conv_rows = 5
        max_talker_rows = 5
        max_threat_rows = 5
        bar_width = 15
    elif term_height <= 48:
        max_proto_rows = 6
        max_conv_rows = 7
        max_talker_rows = 7
        max_threat_rows = 7
        bar_width = 20
    else:
        max_proto_rows = 8
        max_conv_rows = 10
        max_talker_rows = 10
        max_threat_rows = 10
        bar_width = 25

    # 1. Summary Information Panel
    rate_str = (
        f"{stats.packets_per_sec:.1f} pps ({format_bytes(stats.bytes_per_sec)}/s)"
        if stats.elapsed_seconds > 0
        else f"{stats.total_packets:,} pkts"
    )
    summary_text = (
        f"Total Packets: [bold cyan]{stats.total_packets:,}[/bold cyan]   "
        f"Volume: [bold cyan]{format_bytes(stats.total_bytes)}[/bold cyan]\n"
        f"Duration: [bold white]{format_elapsed(stats.elapsed_seconds)}[/bold white]   "
        f"Avg Size: [bold yellow]{stats.avg_packet_size:.1f} B[/bold yellow]\n"
        f"Capture Rate: [bold yellow]{rate_str}[/bold yellow]\n"
        f"Unique Hosts: [bold green]{stats.unique_hosts_total}[/bold green]   "
        f"Threats: [{'bold red' if alerts else 'bold green'}]{len(alerts)}[/]"
    )
    summary_panel = Panel(
        Text.from_markup(summary_text),
        title="[bold blue]PCAP Forensic Summary[/bold blue]",
        border_style="blue",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    # 2. Protocol Distribution Table
    proto_table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.SIMPLE_HEAD,
        expand=True,
        padding=(0, 1),
    )
    proto_table.add_column("Protocol", no_wrap=True)
    proto_table.add_column("Count", justify="right", no_wrap=True)
    proto_table.add_column("%", justify="right", no_wrap=True)
    if term_width >= 90:
        proto_table.add_column("Share", justify="left")

    sorted_protos = sorted(
        stats.protocol_counts.items(), key=lambda x: x[1], reverse=True
    )
    displayed_protos = sorted_protos[:max_proto_rows]
    for proto, count in displayed_protos:
        pct = (count / stats.total_packets * 100) if stats.total_packets > 0 else 0
        if term_width >= 90:
            proto_table.add_row(
                protocol_badge(proto),
                f"{count:,}",
                f"{pct:.1f}%",
                build_bar(count, stats.total_packets, bar_width),
            )
        else:
            proto_table.add_row(
                protocol_badge(proto),
                f"{count:,}",
                f"{pct:.1f}%",
            )
    if len(sorted_protos) > max_proto_rows:
        extra_p = len(sorted_protos) - max_proto_rows
        if term_width >= 90:
            proto_table.add_row("[dim]...[/dim]", f"[dim]+{extra_p} more[/dim]", "", "")
        else:
            proto_table.add_row("[dim]...[/dim]", f"[dim]+{extra_p} more[/dim]", "")

    proto_panel = Panel(
        proto_table,
        title="[bold magenta]Protocol Breakdown[/bold magenta]",
        border_style="magenta",
        box=box.ROUNDED,
        padding=(0, 0),
    )

    # 3. Top Network Conversations Table
    conv_items = getattr(stats, "top_conversations", []) or []
    conv_table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAD,
        expand=True,
        padding=(0, 1),
    )
    conv_table.add_column("Endpoint A", overflow="ellipsis", no_wrap=True)
    conv_table.add_column("Endpoint B", overflow="ellipsis", no_wrap=True)
    conv_table.add_column("Packets", justify="right", no_wrap=True)

    displayed_convs = conv_items[:max_conv_rows]
    for conv in displayed_convs:
        conv_table.add_row(
            conv.get("src", "-"),
            conv.get("dst", "-"),
            f"{conv.get('packets', 0):,}",
        )
    if not conv_items:
        conv_table.add_row("[dim]None recorded[/dim]", "-", "-")
    elif len(conv_items) > max_conv_rows:
        conv_table.add_row(
            f"[dim]... +{len(conv_items) - max_conv_rows} more[/dim]",
            "",
            "",
        )

    conv_panel = Panel(
        conv_table,
        title=f"[bold cyan]Top Conversations ({len(conv_items)})[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 0),
    )

    # 4. Top Data Sources (Talkers) Table
    talker_items = getattr(stats, "top_talkers", []) or []
    talkers_table = Table(
        show_header=True,
        header_style="bold green",
        box=box.SIMPLE_HEAD,
        expand=True,
        padding=(0, 1),
    )
    talkers_table.add_column("Host IP", overflow="ellipsis", no_wrap=True)
    talkers_table.add_column("Volume", justify="right", no_wrap=True)
    talkers_table.add_column("Packets", justify="right", no_wrap=True)

    displayed_talkers = talker_items[:max_talker_rows]
    for item in displayed_talkers:
        talkers_table.add_row(
            item.get("ip", "-"),
            format_bytes(item.get("bytes", 0)),
            f"{item.get('packets', 0):,}",
        )
    if not talker_items:
        talkers_table.add_row("[dim]None recorded[/dim]", "-", "-")
    elif len(talker_items) > max_talker_rows:
        talkers_table.add_row(
            f"[dim]... +{len(talker_items) - max_talker_rows} more[/dim]",
            "",
            "",
        )

    talkers_panel = Panel(
        talkers_table,
        title=f"[bold green]Top Data Sources ({len(talker_items)})[/bold green]",
        border_style="green",
        box=box.ROUNDED,
        padding=(0, 0),
    )

    # 5. Flagged Threats Table
    if alerts:
        threat_table = Table(
            show_header=True,
            header_style="bold red",
            box=box.SIMPLE_HEAD,
            expand=True,
            padding=(0, 1),
        )
        threat_table.add_column("Time", width=9, no_wrap=True)
        threat_table.add_column("Severity", width=10, no_wrap=True)
        threat_table.add_column("Threat Rule", overflow="ellipsis", no_wrap=True)
        threat_table.add_column("Message / Context", overflow="fold")

        displayed_threats = alerts[:max_threat_rows]
        for a in displayed_threats:
            t_str = (
                a.timestamp_str[-8:]
                if a.timestamp_str and len(a.timestamp_str) >= 8
                else (a.timestamp_str or "-")
            )
            safe_msg = (a.message or "-").replace("→", "->")
            threat_table.add_row(
                t_str,
                severity_badge(a.severity),
                a.rule_name or "Threat Detected",
                safe_msg,
            )
        if len(alerts) > max_threat_rows:
            extra_threats = len(alerts) - max_threat_rows
            threat_table.add_row(
                "[dim]...[/dim]",
                f"[dim]+{extra_threats}[/dim]",
                "[dim]more threats[/dim]",
                "[dim](all threats preserved in report / export)[/dim]",
            )
        threat_panel = Panel(
            threat_table,
            title=f"[bold red]Flagged Threats ({len(alerts)})[/bold red]",
            border_style="red",
            box=box.ROUNDED,
            padding=(0, 0),
        )
    else:
        threat_panel = Panel(
            Text.from_markup(
                "[bold green]No security threats detected in this capture file.[/bold green]"
            ),
            title="[bold green]Threat Detection[/bold green]",
            border_style="green",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    # Assemble responsive sections based on terminal width
    renderables = []

    # Header / Top section: Side-by-side on wide/medium screens, stacked on narrow screens
    if term_width >= 86:
        top_grid = Table.grid(expand=True)
        top_grid.add_column(ratio=1)
        top_grid.add_column(ratio=1)
        top_grid.add_row(summary_panel, proto_panel)
        renderables.append(top_grid)
    else:
        renderables.append(summary_panel)
        renderables.append(proto_panel)

    # Middle section: Conversations & Data Sources
    if term_width >= 96:
        mid_grid = Table.grid(expand=True)
        mid_grid.add_column(ratio=1)
        mid_grid.add_column(ratio=1)
        mid_grid.add_row(conv_panel, talkers_panel)
        renderables.append(mid_grid)
    else:
        renderables.append(conv_panel)
        renderables.append(talkers_panel)

    # Bottom section: Threats
    renderables.append(threat_panel)

    return Group(*renderables)


def display_pcap_analysis(
    packets: List[PacketInfo],
    stats: StatsSnapshot,
    alerts: List[AlertInfo],
    console_inst: Optional[Console] = None,
):
    """
    Renders the complete responsive PCAP analysis dashboard in TASK_COMPLETE state.
    Transitions state and clears screen to ensure top-of-viewport alignment.
    """
    c = console_inst or console
    screen_manager.set_state(ScreenState.TASK_COMPLETE)

    dashboard_group = render_pcap_forensic_dashboard(stats, alerts, console_inst=c)
    c.print(dashboard_group)
