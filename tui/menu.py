import os
from typing import Dict, Optional

from rich import box
from rich.align import Align
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text

from utils.constants import APP_VERSION
from utils.console import console, screen_manager, ScreenState


def show_main_menu() -> str:
    """Display the main menu and return user's choice under MAIN_MENU screen state."""
    screen_manager.set_state(ScreenState.MAIN_MENU)

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
        padding=(1, 2),
    )

    console.print(Align.center(panel))
    console.print()

    while True:
        choice = Prompt.ask(
            "Select an option",
            choices=["1", "2", "3", "4", "5", "6"],
            default="1",
            console=console,
        )
        if choice in ["1", "2", "3", "4", "5", "6"]:
            return choice


def prompt_capture_settings() -> Dict[str, str]:
    """Ask for interface, target IP filter, BPF filter under TASK_CONFIG screen state."""
    screen_manager.set_state(ScreenState.TASK_CONFIG)
    console.print("[bold cyan]Live Capture Settings[/bold cyan]")
    console.print()
    interface = Prompt.ask("Interface (leave blank for auto-detect)", default="", console=console)
    target_ip = Prompt.ask("Target IP Filter (optional)", default="", console=console)
    bpf_filter = Prompt.ask("BPF Filter (optional)", default="", console=console)

    return {
        "interface": interface,
        "target_ip": target_ip,
        "bpf_filter": bpf_filter,
    }


def prompt_scan_settings() -> Optional[Dict[str, str]]:
    """Interactive profile selection and target configuration under TASK_CONFIG screen state."""
    screen_manager.set_state(ScreenState.TASK_CONFIG)

    from utils.constants import SCAN_TYPES
    from core.scanner import NetworkScanner

    menu_text = Text()
    menu_text.append("\n")
    menu_text.append("   [1]  Discovery           [dim]-sn (Host ping sweep)[/dim]\n", style="bold white")
    menu_text.append("   [2]  Top Ports           [dim]-sS --top-ports 1000 (SYN scan)[/dim]\n", style="bold white")
    menu_text.append("   [3]  Service Detection   [dim]-sS -sV (Service versions)[/dim]\n", style="bold white")
    menu_text.append("   [4]  Version Detection   [dim]-sV (Probe versions)[/dim]\n", style="bold white")
    menu_text.append("   [5]  OS Detection        [dim]-sS -O (Stack fingerprinting)[/dim]\n", style="bold white")
    menu_text.append("   [6]  Comprehensive       [dim]-sS -sV -O (Full audit)[/dim]\n", style="bold white")
    menu_text.append("   [7]  UDP Top Ports       [dim]-sU --top-ports 100 (UDP services)[/dim]\n", style="bold white")
    menu_text.append("   [8]  TCP Connect         [dim]-sT (Unprivileged 3-way)[/dim]\n", style="bold white")
    menu_text.append("   [9]  Fast Discovery      [dim]-sn -T4 (Accelerated sweep)[/dim]\n", style="bold white")
    menu_text.append("   [A]  Aggressive          [dim]-A --top-ports 1000 (High traffic)[/dim]\n", style="bold white")
    menu_text.append("   [B]  IPv6 Discovery      [dim]-6 -sn (IPv6 ping sweep)[/dim]\n", style="bold white")
    menu_text.append("   [C]  Stealth Scan        [dim]-sS -T2 (Polite timing)[/dim]\n", style="bold white")
    menu_text.append("   [Q]  Back to Main Menu\n", style="bold white")

    panel = Panel(
        Align.center(menu_text),
        title="🔍  Network Scan Profiles  🔍",
        subtitle="[dim italic]Scan only systems & networks you are authorized to assess[/dim italic]",
        width=66,
        border_style="cyan",
        padding=(1, 2),
    )

    console.print(Align.center(panel))
    console.print()

    choice_map = {
        "1": "discovery",
        "2": "top_ports",
        "3": "service",
        "4": "version",
        "5": "os_detection",
        "6": "comprehensive",
        "7": "udp_top",
        "8": "tcp_connect",
        "9": "fast_discovery",
        "a": "aggressive",
        "b": "ipv6_discovery",
        "c": "stealth",
    }

    choice = Prompt.ask(
        "Select scan profile",
        choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "q", "A", "B", "C", "Q"],
        default="2",
        console=console,
    ).lower()

    if choice == "q":
        return None

    scan_type = choice_map.get(choice, "top_ports")
    profile_info = SCAN_TYPES.get(scan_type, {})

    # Display profile info panel
    console.print()
    profile_desc = (
        f"Profile: [bold cyan]{profile_info.get('name', scan_type)}[/bold cyan] ({scan_type})\n"
        f"Arguments: [yellow]{profile_info.get('args', '')}[/yellow]\n"
        f"Description: {profile_info.get('description', '')}\n"
        f"Privilege: {'[bold red]Requires Admin/Root[/bold red]' if profile_info.get('requires_admin') else '[green]Unprivileged[/green]'}\n"
        f"Resource Cost: [dim]{profile_info.get('cost', 'Moderate')}[/dim]"
    )
    if "note" in profile_info:
        profile_desc += f"\n[bold blue]Note:[/bold blue] {profile_info['note']}"
    if "warning" in profile_info:
        profile_desc += f"\n[bold red]⚠️  WARNING:[/bold red] {profile_info['warning']}"

    console.print(Panel(profile_desc, title="Selected Scan Configuration", border_style="blue", width=66))
    console.print()

    # Prompt and validate target
    scanner = NetworkScanner()
    while True:
        target = Prompt.ask("Target IP, Subnet, or Hostname (or press Enter to cancel)", default="", console=console).strip()
        if not target:
            return None
        try:
            validated = scanner.validate_target(target)
            return {
                "target": validated,
                "scan_type": scan_type,
            }
        except ValueError as e:
            console.print(f"[bold red]Invalid target:[/bold red] {e}")
            console.print("[dim]Examples: 192.168.1.0/24, 10.0.0.1, fe80::1, scanme.nmap.org[/dim]")


from utils.path_helpers import (
    clean_pcap_path_input,
    resolve_pcap_path,
    find_similar_pcap,
    get_available_pcaps_in_dir,
)
from pathlib import Path


def prompt_pcap_path() -> str:
    """
    Interactive PCAP file path prompt under TASK_CONFIG screen state.
    Features:
    - Preserves absolute Windows paths, drive letters, backslashes, and quotes.
    - Handles relative paths (e.g. exports/test1.pcap).
    - Intelligent 'Did you mean?' typo suggestions and confirmation.
    - Numbered quick-selection for existing PCAPs in export/current directories.
    - Graceful empty-input and cancellation handling.
    """
    screen_manager.set_state(ScreenState.TASK_CONFIG)
    console.print("[bold cyan]📂 Analyze PCAP File[/bold cyan]")
    console.print()

    # Discover available PCAPs in exports or current working directory for quick-select
    cwd = Path.cwd()
    search_dirs = [cwd / "exports", cwd]
    available_pcaps = []
    seen_paths = set()
    for d in search_dirs:
        for p in get_available_pcaps_in_dir(d, limit=6):
            if p.resolve() not in seen_paths:
                seen_paths.add(p.resolve())
                available_pcaps.append(p)

    if available_pcaps:
        console.print("[bold green]Available PCAP captures:[/bold green]")
        for idx, pcap_path in enumerate(available_pcaps[:5], 1):
            size_kb = pcap_path.stat().st_size / 1024.0 if pcap_path.exists() else 0
            rel_str = str(pcap_path.relative_to(cwd)) if pcap_path.is_relative_to(cwd) else str(pcap_path)
            console.print(f"  [{idx}] {rel_str} [dim]({size_kb:.1f} KB)[/dim]")
        console.print()

    while True:
        raw_input = Prompt.ask(
            "Enter PCAP file path or selection number (or '[bold]q[/bold]' to cancel)",
            default="",
            console=console,
        )

        if not raw_input.strip():
            console.print("[dim yellow]Please enter a PCAP file path or select a number from above.[/dim yellow]")
            continue

        if raw_input.strip().lower() in ("q", "quit", "exit", "cancel"):
            return ""

        # Check for numeric shortcut selection
        if raw_input.strip().isdigit():
            choice_num = int(raw_input.strip())
            if 1 <= choice_num <= len(available_pcaps):
                selected = available_pcaps[choice_num - 1]
                if selected.is_file():
                    return str(selected.resolve())

        # Resolve and validate path
        target_path = resolve_pcap_path(raw_input)
        if not target_path:
            console.print("[red]Invalid path format.[/red]")
            continue

        if target_path.is_file():
            return str(target_path.resolve())

        if target_path.is_dir():
            console.print(f"[bold red]Error:[/bold red] '{target_path}' is a directory, not a file.")
            dir_pcaps = get_available_pcaps_in_dir(target_path, limit=5)
            if dir_pcaps:
                console.print(f"[yellow]PCAP files in this directory:[/yellow]")
                for p in dir_pcaps:
                    console.print(f"  • {p.name}")
            continue

        # File does not exist — provide intelligent 'Did you mean?' suggestion
        console.print()
        console.print(f"[bold red]PCAP file not found:[/bold red]")
        console.print(f"  {target_path}")

        suggested = find_similar_pcap(target_path, cutoff=0.45)
        if suggested and suggested.is_file():
            console.print()
            console.print(f"[bold yellow]Possible matching file:[/bold yellow]")
            console.print(f"  [cyan]{suggested.resolve()}[/cyan]")
            console.print()
            if Confirm.ask("Did you mean this file?", default=True, console=console):
                return str(suggested.resolve())

        console.print()


def prompt_export_settings() -> Dict[str, str]:
    """Ask for format and filename under TASK_CONFIG screen state."""
    screen_manager.set_state(ScreenState.TASK_CONFIG)
    console.print("[bold cyan]Export Settings[/bold cyan]")
    console.print()
    fmt = Prompt.ask("Export Format", choices=["CSV", "PCAP", "JSON"], default="CSV", console=console)
    filename = Prompt.ask("Output Filename", default="", console=console)

    return {
        "format": fmt.lower(),
        "filename": filename,
    }

