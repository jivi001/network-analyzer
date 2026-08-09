import time
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from storage.models import ScanResult, HostInfo

console = Console()


def display_scan_progress(target: str, scan_type: str):
    """Show Rich spinner during scan."""
    console.print(f"[cyan]Initiating {scan_type} scan on {target}...[/cyan]")


def display_scan_results(result: ScanResult):
    """Render scan results as Rich tables."""
    console.clear()

    # Summary panel
    summary_text = (
        f"Target: [bold cyan]{result.target}[/bold cyan]\n"
        f"Scan Type: [bold cyan]{result.scan_type}[/bold cyan]\n"
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
        console.print("[yellow]No active hosts found matching criteria.[/yellow]")
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
        open_ports_summary = ", ".join(host.open_ports) if host.open_ports else "None"
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
