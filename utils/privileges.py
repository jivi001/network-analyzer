"""
privileges.py — System privilege checks for raw socket access.
Ensures the script runs with required admin/root permissions.
"""

import os
import sys

from utils.console import console


def check_privileges(require_exit: bool = True) -> bool:
    """
    Check if the script is running with elevated privileges.
    
    Raw packet sniffing (Scapy) and certain Nmap scans require
    root (Linux/macOS) or Administrator (Windows) permissions.
    
    Args:
        require_exit: If True, exits the program on failure.
                      If False, returns False without exiting.
    
    Returns:
        True if running with elevated privileges, False otherwise.
    """
    is_elevated = False

    if sys.platform == "win32":
        # Windows: Check if running as Administrator
        try:
            import ctypes
            is_elevated = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            is_elevated = False
    else:
        # Linux / macOS: Check for root (UID 0)
        is_elevated = os.geteuid() == 0

    if not is_elevated:
        console.print()
        console.print("[bold red][!] Privilege Check Failed[/bold red]")
        console.print()
        console.print(
            "  Raw packet sniffing and network scanning require elevated privileges."
        )
        console.print()

        if sys.platform == "win32":
            console.print("  [yellow]Windows:[/yellow] Right-click your terminal and select")
            console.print('  [bold]"Run as Administrator"[/bold], then run the script again.')
        else:
            console.print("  [yellow]Linux/macOS:[/yellow] Run with sudo:")
            console.print("  [bold]sudo python3 sentinel.py[/bold]")

        console.print()

        if require_exit:
            sys.exit(1)

    return is_elevated


def check_nmap_installed() -> bool:
    """
    Check if Nmap is installed and accessible in PATH.
    
    Returns:
        True if nmap is found, False otherwise.
    """
    import shutil

    nmap_path = shutil.which("nmap")
    if nmap_path is None:
        console.print()
        console.print("[bold yellow][!] Nmap Not Found[/bold yellow]")
        console.print()
        console.print("  Network scanning (Mode 2) requires Nmap to be installed.")
        console.print()

        if sys.platform == "win32":
            console.print("  [yellow]Install:[/yellow] Download from [link]https://nmap.org/download.html[/link]")
            console.print("  Make sure to add Nmap to your system PATH during installation.")
        elif sys.platform == "darwin":
            console.print("  [yellow]Install:[/yellow] brew install nmap")
        else:
            console.print("  [yellow]Install:[/yellow] sudo apt install nmap  (Debian/Ubuntu)")
            console.print("           sudo dnf install nmap  (Fedora/RHEL)")

        console.print()
        return False

    return True


def check_npcap_installed() -> bool:
    """
    Check if Npcap (Windows) or libpcap (Linux/macOS) is available.
    Required for raw packet capture with Scapy.
    
    Returns:
        True if pcap library is available, False otherwise.
    """
    if sys.platform == "win32":
        # Check for Npcap DLL
        npcap_path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "Npcap"
        )
        if not os.path.isdir(npcap_path):
            console.print()
            console.print("[bold yellow][!] Npcap Not Found[/bold yellow]")
            console.print()
            console.print("  Live packet capture requires Npcap on Windows.")
            console.print("  [yellow]Install:[/yellow] Download from [link]https://npcap.com/#download[/link]")
            console.print('  During install, check [bold]"Install Npcap in WinPcap API-compatible Mode"[/bold]')
            console.print()
            return False
    # On Linux/macOS, libpcap is typically pre-installed
    return True


def run_all_checks(require_admin: bool = True) -> dict:
    """
    Run all system prerequisite checks and return results.
    
    Args:
        require_admin: Whether to enforce admin privileges.
    
    Returns:
        Dict with check results: {
            'privileges': bool,
            'nmap': bool,
            'pcap': bool,
        }
    """
    results = {
        "privileges": check_privileges(require_exit=require_admin),
        "nmap": check_nmap_installed(),
        "pcap": check_npcap_installed(),
    }
    return results
