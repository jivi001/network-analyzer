from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from storage.models import SessionInfo, AlertInfo, HostInfo
from utils.constants import format_bytes
from tui.helpers import format_alert_row, format_host_row

console = Console()


def display_history_menu() -> str:
    """Sub-menu for history mode."""
    console.clear()
    console.print("\n[bold cyan]📊 History & Intelligence Browser[/bold cyan]\n")
    console.print("   [1] 🕒 Recent Sessions")
    console.print("   [2] 🚨 All Alerts History")
    console.print("   [3] 🖥️ Discovered Hosts")
    console.print("   [4] 🔍 Search Database")
    console.print("   [5] 📥 Import JSON Data")
    console.print("   [6] ↩️  Back to Main Menu")
    console.print()

    while True:
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6"], default="1")
        if choice in ["1", "2", "3", "4", "5", "6"]:
            return choice


def display_sessions(sessions: List[SessionInfo]):
    """Rich table of sessions."""
    console.clear()
    if not sessions:
        console.print("[yellow]No sessions recorded yet.[/yellow]")
        return

    table = Table(title="Recent Sessions History", show_header=True, header_style="bold magenta", expand=True)
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
    """Paginated alert table."""
    console.clear()
    if not alerts:
        console.print("[yellow]No alerts recorded in database.[/yellow]")
        return

    table = Table(title=f"Security Alerts ({len(alerts)})", show_header=True, header_style="bold red", expand=True)
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
    console.clear()
    if not hosts:
        console.print("[yellow]No discovered hosts recorded yet.[/yellow]")
        return

    table = Table(title=f"Discovered Hosts ({len(hosts)})", show_header=True, header_style="bold green", expand=True)
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
    console.clear()

    # Summary panel
    summary = (
        f"Session ID: [bold]{session.id}[/bold]\n"
        f"Type: [cyan]{session.session_type}[/cyan]\n"
        f"Interface / Target: [white]{session.interface or session.target or 'N/A'}[/white]\n"
        f"Status: [green]{session.status}[/green]\n"
        f"Total Packets: [bold]{session.packet_count:,}[/bold]\n"
        f"Total Volume: [bold]{format_bytes(session.total_bytes)}[/bold]\n"
        f"Alerts Flagged: [bold red]{session.alert_count}[/bold red]"
    )
    console.print(Panel(summary, title=f"Session #{session.id} Overview", border_style="blue"))
    console.print()

    if alerts:
        display_alerts_history(alerts)
