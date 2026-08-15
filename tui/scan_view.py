import time
from typing import List

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from storage.models import ScanResult, HostInfo
from utils.console import console, ScreenState, screen_manager


def display_scan_progress(target: str, scan_type: str, scan_args: str = ""):
    """Show rich panel during scan execution in TASK_RUNNING state."""
    screen_manager.set_state(ScreenState.TASK_RUNNING)
    from utils.constants import SCAN_TYPES
    profile_info = SCAN_TYPES.get(scan_type, {})
    profile_name = profile_info.get("name", scan_type)
    args_str = scan_args or profile_info.get("args", "")

    progress_body = (
        f"Target: [bold cyan]{target}[/bold cyan]\n"
        f"Profile: [bold yellow]{profile_name}[/bold yellow] ({scan_type})\n"
        f"Arguments: [dim]{args_str}[/dim]\n"
        f"Status: [bold green]Running...[/bold green]"
    )
    if profile_info.get("warning"):
        progress_body += f"\n[bold red]Note:[/bold red] {profile_info['warning']}"

    console.print()
    console.print(
        Panel(
            progress_body,
            title="SCAN IN PROGRESS",
            border_style="cyan",
            box=box.ASCII,
        )
    )
    console.print()


def display_scan_results(result: ScanResult):
    """Render scan results as Rich tables in TASK_COMPLETE state."""
    screen_manager.set_state(ScreenState.TASK_COMPLETE)
    from utils.constants import SCAN_TYPES
    profile_name = SCAN_TYPES.get(result.scan_type, {}).get("name", result.scan_type)

    # Summary panel
    summary_text = (
        f"Target: [bold cyan]{result.target}[/bold cyan]\n"
        f"Profile: [bold cyan]{profile_name}[/bold cyan] ({result.scan_type})\n"
        f"Scan Arguments: [dim]{result.scan_args}[/dim]\n"
        f"Hosts Found: [bold green]{result.hosts_found}[/bold green]\n"
        f"Duration: [bold yellow]{result.duration_sec:.2f}s[/bold yellow]"
    )
    console.print(
        Panel(
            Text.from_markup(summary_text),
            title="Scan Summary",
            border_style="blue",
        )
    )
    console.print()

    if not result.hosts:
        console.print("[yellow]No hosts found.[/yellow]")
        return

    # Host table
    host_table = Table(
        show_header=True, header_style="bold magenta", expand=True
    )
    host_table.add_column("IP Address")
    host_table.add_column("Hostname")
    host_table.add_column("State")
    host_table.add_column("Open Ports Count")
    host_table.add_column("Services Overview")
    host_table.add_column("OS Guess")

    for host in result.hosts:
        open_ports_summary = ", ".join(str(p) for p in host.open_ports) if host.open_ports else "None"
        if len(open_ports_summary) > 40:
            open_ports_summary = open_ports_summary[:37] + "..."

        host_table.add_row(
            host.ip_address,
            host.hostname or "N/A",
            host.state or "up",
            str(len(host.open_ports)),
            open_ports_summary,
            host.os_guess or "Unknown",
        )

    console.print(host_table)
    console.print()

    # Detail table for hosts with open ports
    for host in result.hosts:
        if host.open_ports:
            display_host_detail(host)


def display_host_detail(host: HostInfo):
    """Detailed view of single host open ports."""
    port_table = Table(show_header=True, header_style="bold yellow", expand=True)
    port_table.add_column("Port/Proto")
    port_table.add_column("Service & Version")

    if host.services:
        for port_str, svc_info in host.services.items():
            port_table.add_row(port_str, svc_info or "Unknown")
    else:
        for p in host.open_ports:
            port_table.add_row(str(p), "Open")

    console.print(
        Panel(
            port_table,
            title=f"Port Details for {host.ip_address} ({host.hostname or 'No Hostname'})",
            border_style="cyan",
        )
    )
