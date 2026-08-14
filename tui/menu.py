import os
from typing import Dict, Optional

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.align import Align
from rich.text import Text

from utils.constants import APP_VERSION

console = Console()


def clear_screen():
    """Clear and separate terminal screens, including terminals that capture ANSI poorly."""
    console.clear()
    console.print()


def show_main_menu() -> str:
    """Display the main menu and return user's choice."""
    clear_screen()

    menu_text = Text()
    menu_text.append("\n")
    menu_text.append("   [1]  🔴 Live Capture\n", style="bold white")
    menu_text.append("   [2]  🔍 Network Scan\n", style="bold white")
    menu_text.append("   [3]  📂 Analyze PCAP File\n", style="bold white")
    menu_text.append("   [4]  📊 View History\n", style="bold white")
    menu_text.append("   [5]  ⚙️  Settings\n", style="bold white")
    menu_text.append("   [6]  🚪 Exit\n", style="bold white")
    
    panel = Panel(
        Align.center(menu_text),
        title=f"🛡️  my-sentinel v{APP_VERSION} 🛡️",
        subtitle="Network Traffic Analyzer & Scanner",
        width=54,
        border_style="blue",
        padding=(1, 2)
    )
    
    console.print(Align.center(panel))
    console.print()
    
    while True:
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6"], default="1")
        if choice in ["1", "2", "3", "4", "5", "6"]:
            return choice

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
        "bpf_filter": bpf_filter
    }


def prompt_scan_settings() -> Dict[str, str]:
    """Ask for target IP/subnet and scan type."""
    clear_screen()
    console.print("[bold cyan]Network Scan Settings[/bold cyan]")
    while True:
        target = Prompt.ask("Target IP or Subnet (e.g., 192.168.1.0/24)")
        if target:
            break
        console.print("[red]Target is required.[/red]")

    scan_type = Prompt.ask(
        "Scan Type",
        choices=["quick", "port", "full", "stealth"],
        default="quick",
    )

    return {
        "target": target,
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
    console.print("\n[bold cyan]Export Settings[/bold cyan]")
    fmt = Prompt.ask("Export Format", choices=["CSV", "PCAP", "JSON"], default="CSV")
    filename = Prompt.ask("Output Filename", default="")
    
    return {
        "format": fmt.lower(),
        "filename": filename
    }
