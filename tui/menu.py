import os
from typing import Dict, Optional

from rich import box
from rich.align import Align
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from utils.constants import APP_VERSION
from utils.console import console


def clear_screen():
    """Clear screen cleanly."""
    console.clear()


def show_main_menu() -> str:
    """Display the main menu and return user's choice."""
    clear_screen()

    menu_text = Text()
    menu_text.append("\n")
    menu_text.append("   [1]  Live Capture\n", style="bold white")
    menu_text.append("   [2]  Network Scan\n", style="bold white")
    menu_text.append("   [3]  Analyze PCAP File\n", style="bold white")
    menu_text.append("   [4]  View History\n", style="bold white")
    menu_text.append("   [5]  Settings\n", style="bold white")
    menu_text.append("   [6]  Exit\n", style="bold white")

    panel = Panel(
        Align.center(menu_text),
        title=f"my-sentinel v{APP_VERSION}",
        subtitle="Network Traffic Analyzer & Scanner",
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


def prompt_capture_settings() -> Dict[str, str]:
    """Ask for interface, target IP filter, BPF filter."""
    clear_screen()
    console.print("[bold cyan]Live Capture Settings[/bold cyan]")
    interface = Prompt.ask("Interface (leave blank for default)", default="")
    target_ip = Prompt.ask("Target IP Filter (optional)", default="")
    bpf_filter = Prompt.ask("BPF Filter (optional)", default="")

    return {
        "interface": interface,
        "target_ip": target_ip,
        "bpf_filter": bpf_filter,
    }


def prompt_scan_settings() -> Optional[Dict[str, str]]:
    """Ask for target IP/subnet and scan profile from the enhanced list."""
    clear_screen()
    console.print("[bold cyan]Network Scan Settings[/bold cyan]")
    console.print("[dim]Scan only systems and networks you own or are explicitly authorized to assess.[/dim]")
    console.print()

    target = Prompt.ask("Target IP, Subnet, or Hostname (e.g. 192.168.1.0/24, ::1, example.com)")
    if not target or not target.strip():
        console.print("[red]Target is required.[/red]")
        return None

    console.print()
    console.print("[bold cyan]Select Scan Profile:[/bold cyan]")
    console.print("  [1] Live Host Discovery   (-sn)")
    console.print("  [2] Fast Discovery        (-sn -T4)")
    console.print("  [3] TCP Top Ports         (-sS --top-ports 1000)")
    console.print("  [4] Service Detection     (-sS -sV --top-ports 1000)")
    console.print("  [5] Version Enumeration   (-sV --top-ports 1000)")
    console.print("  [6] OS Detection          (-sS -O --top-ports 1000)")
    console.print("  [7] Comprehensive         (-sS -sV -O --top-ports 1000)")
    console.print("  [8] UDP Top Ports         (-sU --top-ports 100 - Slow)")
    console.print("  [9] TCP Connect           (-sT --top-ports 1000)")
    console.print("  [A] Aggressive Assessment (-A --top-ports 1000 - Advanced)")
    console.print("  [B] IPv6 Discovery        (-6 -sn)")
    console.print("  [S] Stealth Scan          (-sS -T2 --top-ports 100)")
    console.print()

    choice_map = {
        "1": "discovery",
        "2": "fast_discovery",
        "3": "top_ports",
        "4": "service",
        "5": "version",
        "6": "os_detection",
        "7": "comprehensive",
        "8": "udp_top",
        "9": "tcp_connect",
        "a": "aggressive",
        "b": "ipv6_discovery",
        "s": "stealth",
    }

    choice = Prompt.ask(
        "Select profile",
        choices=list(choice_map.keys()),
        default="3",
    ).lower()

    scan_type = choice_map.get(choice, "top_ports")

    from utils.constants import SCAN_TYPES
    profile_info = SCAN_TYPES.get(scan_type, {})
    if profile_info.get("warning"):
        console.print(f"\n[bold yellow]⚠️ WARNING:[/bold yellow] {profile_info['warning']}")
    if profile_info.get("requires_admin"):
        console.print("[dim yellow]Note: This scan type may require Administrator/root privileges.[/dim yellow]")

    return {
        "target": target.strip(),
        "scan_type": scan_type,
    }


def prompt_pcap_path() -> str:
    """Ask for PCAP file path with validation."""
    clear_screen()
    console.print("[bold cyan]Analyze PCAP File[/bold cyan]")
    while True:
        filepath = Prompt.ask("Path to PCAP file")
        if os.path.exists(filepath):
            return filepath
        console.print(f"[red]Error: File '{filepath}' not found.[/red]")


def prompt_export_settings() -> Dict[str, str]:
    """Ask for format and filename."""
    console.print()
    console.print("[bold cyan]Export Settings[/bold cyan]")
    fmt = Prompt.ask("Export Format", choices=["CSV", "PCAP", "JSON"], default="CSV")
    filename = Prompt.ask("Output Filename", default="")

    return {
        "format": fmt.lower(),
        "filename": filename,
    }
