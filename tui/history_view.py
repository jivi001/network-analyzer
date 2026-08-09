from typing import List

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from storage.models import AlertInfo, HostInfo, SessionInfo
from tui.helpers import format_alert_row, format_host_row
from utils.constants import format_bytes
from tui.menu import clear_screen

console = Console()


def display_history_menu() -> str:
    """Sub-menu for history mode."""
    clear_screen()

    menu_text = Text()
    menu_text.append("\n")
    menu_text.append("   [1]  Recent Sessions\n", style="bold white")
    menu_text.append("   [2]  All Alerts History\n", style="bold white")
    menu_text.append("   [3]  Discovered Hosts\n", style="bold white")
    menu_text.append("   [4]  Search Database\n", style="bold white")
    menu_text.append("   [5]  Import JSON Data\n", style="bold white")
    menu_text.append("   [6]  Back to Main Menu\n", style="bold white")

    panel = Panel(
        Align.center(menu_text),
        title="History & Intelligence Browser",
        subtitle="my-sentinel",
        width=54,
        box=box.ASCII,
        border_style="blue",
        padding=(1, 2),
    )

    console.print(Align.center(panel))
    console.print()

    return Prompt.ask(
        "Select an option",
        choices=["1", "2", "3", "4", "5", "6"],
        default="1",
    )


def display_sessions(sessions: List[SessionInfo]):
    """Rich table of sessions."""
    clear_screen()
    if not sessions:
        console.print(Panel("[yellow]No sessions recorded yet.[/yellow]", title="Recent Sessions", box=box.ASCII))
        return

    table = Table(title="Recent Sessions History", show_header=True, header_style="bold magenta", expand=True, box=box.ASCII)
    table.add_column("ID", width=6, justify="right")
    table.add_column("Type", width=14)
    table.add_column("Start Time", width=20)
    table.add_column("End Time", width=20)
    table.add_column("Packets", justify="right")
    table.add_column("Volume", justify="right")
    table.add_column("Alerts", justify="right")
    table.add_column("Status")

    for s in sessions:
        table.add_row(
            str(s.id),
            s.session_type or "",
            str(s.start_time or ""),
            str(s.end_time or ""),
            f"{s.packet_count:,}",
            format_bytes(s.total_bytes),
            str(s.alert_count),
            s.status or "",
        )

    console.print(table)


def display_alerts_history(alerts: List[AlertInfo]):
    """Display alert table."""
    clear_screen()
    if not alerts:
        console.print(Panel("[yellow]No alerts recorded in database.[/yellow]", title="Security Alerts", box=box.ASCII))
        return

    table = Table(title=f"Security Alerts ({len(alerts)})", show_header=True, header_style="bold red", expand=True, box=box.ASCII)
    table.add_column("Time", width=20)
    table.add_column("Severity", width=12)
    table.add_column("Rule Name")
    table.add_column("Source IP")
    table.add_column("Dest IP")
    table.add_column("Message")

    for alert in alerts:
        table.add_row(*format_alert_row(alert))

    console.print(table)


def display_hosts_table(hosts: List[HostInfo]):
    """Discovered hosts table."""
    clear_screen()
    if not hosts:
        console.print(Panel("[yellow]No discovered hosts recorded yet.[/yellow]", title="Discovered Hosts", box=box.ASCII))
        return

    table = Table(title=f"Discovered Hosts ({len(hosts)})", show_header=True, header_style="bold green", expand=True, box=box.ASCII)
    table.add_column("IP Address")
    table.add_column("MAC Address")
    table.add_column("Hostname")
    table.add_column("Open Ports")
    table.add_column("OS Guess")
    table.add_column("First Seen")
    table.add_column("Last Seen")
    table.add_column("Source")

    for host in hosts:
        table.add_row(*format_host_row(host))

    console.print(table)


def display_session_detail(session: SessionInfo, alerts: List[AlertInfo]):
    """Drill into a session."""
    clear_screen()

    summary = (
        f"Session ID: [bold]{session.id}[/bold]\n"
        f"Type: [cyan]{session.session_type}[/cyan]\n"
        f"Interface / Target: [white]{session.interface or session.target or 'N/A'}[/white]\n"
        f"Status: [green]{session.status}[/green]\n"
        f"Total Packets: [bold]{session.packet_count:,}[/bold]\n"
        f"Total Volume: [bold]{format_bytes(session.total_bytes)}[/bold]\n"
        f"Alerts Flagged: [bold red]{session.alert_count}[/bold red]"
    )
    console.print(Panel(summary, title=f"Session #{session.id} Overview", border_style="blue", box=box.ASCII))
    console.print()

    if alerts:
        table = Table(title=f"Security Alerts ({len(alerts)})", show_header=True, header_style="bold red", expand=True, box=box.ASCII)
        table.add_column("Time", width=20)
        table.add_column("Severity", width=12)
        table.add_column("Rule Name")
        table.add_column("Source IP")
        table.add_column("Dest IP")
        table.add_column("Message")
        for alert in alerts:
            table.add_row(*format_alert_row(alert))
        console.print(table)
