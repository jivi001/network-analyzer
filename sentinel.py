#!/usr/bin/env python3
"""
sentinel.py — my-sentinel Entry Point

A menu-driven CLI network traffic analyzer and security scanner.
Unifies live packet capture, Nmap scanning, PCAP forensics,
and historical intelligence into a single Python tool.

Usage:
    python sentinel.py                  # Interactive menu mode
    python sentinel.py --capture        # Jump directly to live capture
    python sentinel.py --scan <target>  # Quick scan a target
    python sentinel.py --pcap <file>    # Analyze a PCAP file
    python sentinel.py --mask           # Enable privacy masking
"""

import argparse
import os
import sys
import time
import threading
from collections import deque
from datetime import datetime

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

from rich.console import Console
from rich.live import Live
from rich.prompt import Prompt, Confirm

# my-sentinel modules
from utils.constants import APP_BANNER, APP_VERSION, APP_NAME, DASHBOARD_REFRESH_MS
from utils.privileges import check_privileges, check_nmap_installed, check_npcap_installed
from utils.privacy import PrivacyFilter

from storage.models import PacketInfo, SessionInfo, StatsSnapshot
from storage.database import Database
from storage.exporter import Exporter

from core.sniffer import PacketSniffer
from core.processor import process_packet
from core.stats import StatsAggregator
from core.scanner import NetworkScanner
from core.pcap_loader import PcapLoader

from detection.rule_engine import RuleEngine
from detection.anomaly import AnomalyDetector
from detection.arp_monitor import ArpMonitor
from detection.alerts import AlertManager
from detection.pipeline import PacketDetectionPipeline

from tui.menu import (
    show_main_menu,
    prompt_capture_settings,
    prompt_scan_settings,
    prompt_pcap_path,
    prompt_export_settings,
)
from tui.dashboard import LiveDashboard
from tui.scan_view import display_scan_results, display_scan_progress
from tui.pcap_view import display_pcap_analysis, display_pcap_loading
from tui.history_view import (
    display_history_menu,
    display_sessions,
    display_alerts_history,
    display_hosts_table,
    display_session_detail,
)
from tui.helpers import format_elapsed

console = Console()


def load_config() -> dict:
    """Load configuration from config.yaml if available, otherwise use defaults."""
    config = {
        "database_path": "sentinel_data.db",
        "packet_buffer_size": 500,
        "refresh_fps": 4,
        "default_filter": "",
        "privacy_mask": False,
        "rules_directory": "rules",
        "dedup_window": 60,
        "max_alerts": 100,
        "export_directory": "exports",
    }

    try:
        import yaml

        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                yaml_config = yaml.safe_load(f)

            if yaml_config:
                # Flatten nested config
                for section in yaml_config.values():
                    if isinstance(section, dict):
                        config.update(section)
    except ImportError:
        pass  # PyYAML not installed, use defaults
    except Exception:
        pass  # Config file issues, use defaults

    return config


def run_live_capture(config: dict, db: Database, privacy: PrivacyFilter):
    """
    Mode 1: Live Capture — Real-time packet sniffing with TUI dashboard.
    """
    settings = prompt_capture_settings()
    if settings is None:
        return

    interface = settings.get("interface", "")
    target_ip = settings.get("target_ip", "")
    bpf_filter = settings.get("bpf_filter", config.get("default_filter", ""))

    # If target IP specified, add to BPF filter
    if target_ip:
        ip_filter = f"host {target_ip}"
        bpf_filter = f"({bpf_filter}) and {ip_filter}" if bpf_filter else ip_filter

    # Initialize components
    stats = StatsAggregator()
    alert_manager = AlertManager(
        max_alerts=config.get("max_alerts", 100),
        dedup_window=config.get("dedup_window", 60),
    )
    rule_engine = RuleEngine(rules_dir=config.get("rules_directory", "rules"))
    anomaly_detector = AnomalyDetector()
    arp_monitor = ArpMonitor()
    detection_pipeline = PacketDetectionPipeline(rule_engine, anomaly_detector, arp_monitor)
    sniffer = PacketSniffer()
    dashboard = LiveDashboard(stats, alert_manager, privacy)

    packet_buffer = deque(maxlen=config.get("packet_buffer_size", 500))
    raw_packets = []
    packet_counter = [0]  # Mutable counter for closure
    lock = threading.Lock()

    # Create session record
    session = SessionInfo(
        session_type="capture",
        start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        interface=interface or "auto",
        filter_applied=bpf_filter,
        status="active",
    )
    session_id = db.create_session(session)

    def on_packet(raw_pkt):
        """Callback for each captured packet."""
        with lock:
            packet_counter[0] += 1
            pkt_info = process_packet(raw_pkt, packet_counter[0])

            if pkt_info:
                # Update stats
                stats.update(pkt_info)

                # Run detection
                for alert in detection_pipeline.evaluate(pkt_info):
                    alert.session_id = session_id
                    if alert_manager.add(alert):
                        db.save_alert(alert)

                # Buffer for display
                packet_buffer.append(pkt_info)
                raw_packets.append(raw_pkt)

    # Start capture
    console.print()
    console.print(f"[bold green]Starting capture[/bold green] on {interface or 'default interface'}...")
    if bpf_filter:
        console.print(f"  Filter: [yellow]{bpf_filter}[/yellow]")
    console.print("  Press [bold]Ctrl+C[/bold] to stop capture")
    console.print()

    try:
        sniffer.start(
            interface=interface if interface else None,
            bpf_filter=bpf_filter if bpf_filter else None,
            callback=on_packet,
        )
        stats.start_rate_calculator()

        refresh_interval = 1.0 / config.get("refresh_fps", 4)
        paused = False

        with Live(
            dashboard.get_renderable(),
            console=console,
            refresh_per_second=config.get("refresh_fps", 4),
            transient=True,
        ) as live:
            while sniffer.is_running():
                try:
                    if not paused:
                        dashboard.update(list(packet_buffer))
                        live.update(dashboard.get_renderable())
                    
                    # Keyboard handling for Windows
                    if sys.platform == 'win32':
                        import msvcrt
                        while msvcrt.kbhit():
                            key = msvcrt.getch().decode('utf-8', 'ignore').lower()
                            if key == 'q':
                                sniffer.stop()
                            elif key == 'p':
                                paused = not paused
                            elif key == 'f':
                                live.stop()
                                try:
                                    new_filter = Prompt.ask("BPF Filter (blank to clear)", default="")
                                    bpf_filter = new_filter
                                    sniffer.restart_with_filter(bpf_filter if bpf_filter else None)
                                    dashboard.update(list(packet_buffer))
                                except Exception as e:
                                    console.print(f"[bold red]Filter change failed:[/bold red] {e}")
                                finally:
                                    live.start(refresh=True)
                            elif key == 'e':
                                exporter = Exporter()
                                export_dir = config.get("export_directory", "exports")
                                filename = exporter.generate_filename("capture", "json")
                                filepath = os.path.join(export_dir, filename)
                                try:
                                    exporter.export_json(
                                        filepath,
                                        alert_manager.get_all(),
                                        stats.get_snapshot(),
                                    )
                                    console.print(f"[green]Exported to:[/green] {filepath}")
                                except Exception as e:
                                    console.print(f"[bold red]Export failed:[/bold red] {e}")

                    time.sleep(refresh_interval)
                except KeyboardInterrupt:
                    break

    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[bold red]Error during capture:[/bold red] {e}")
    finally:
        sniffer.stop()
        stats.stop_rate_calculator()

    # End session
    snapshot = stats.get_snapshot()
    db.end_session(
        session_id=session_id,
        packet_count=snapshot.total_packets,
        total_bytes=snapshot.total_bytes,
        alert_count=alert_manager.get_count(),
    )
    db.save_packet_summary(session_id, snapshot)

    console.print()
    console.print(f"[bold green]Capture stopped.[/bold green]")
    console.print(f"  Packets: {snapshot.total_packets:,} | Bytes: {snapshot.total_bytes:,} | Alerts: {alert_manager.get_count()}")
    console.print()

    # Offer export
    if snapshot.total_packets > 0 and Confirm.ask("Export capture data?", default=False):
        export_settings = prompt_export_settings()
        if export_settings:
            exporter = Exporter()
            exporter.ensure_export_dir(config.get("export_directory", "exports"))

            fmt = export_settings.get("format", "csv").lower()
            filename = export_settings.get(
                "filename",
                exporter.generate_filename("capture", fmt),
            ) or exporter.generate_filename("capture", fmt)
            filepath = os.path.join(config.get("export_directory", "exports"), filename)

            try:
                if fmt == "csv":
                    exporter.export_csv(filepath, list(packet_buffer), snapshot)
                elif fmt == "pcap":
                    exporter.export_pcap(filepath, raw_packets)
                elif fmt == "json":
                    exporter.export_json(filepath, alert_manager.get_all(), snapshot)
                else:
                    raise ValueError(f"Unsupported export format: {fmt}")
            except Exception as e:
                filepath = ""
                console.print(f"[bold red]Export failed:[/bold red] {e}")

            if filepath:
                console.print(f"[green]Exported to:[/green] {filepath}")


def run_network_scan(config: dict, db: Database):
    """
    Mode 2: Network Scan — Active host discovery and port scanning with Nmap.
    """
    if not check_nmap_installed():
        console.print("[yellow]Network scanning requires Nmap. Install it and try again.[/yellow]")
        return

    settings = prompt_scan_settings()
    if settings is None:
        return

    target = settings.get("target", "")
    scan_type = settings.get("scan_type", "quick")

    # Create session
    session = SessionInfo(
        session_type="scan",
        start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=target,
        status="active",
    )
    session_id = db.create_session(session)

    scanner = NetworkScanner()

    console.print()
    display_scan_progress(target, scan_type)

    try:
        if scan_type == "quick":
            hosts = scanner.ping_sweep(target)
            from storage.models import ScanResult

            result = ScanResult(
                session_id=session_id,
                target=target,
                scan_type=scan_type,
                hosts_found=len(hosts),
                hosts=hosts,
                start_time=session.start_time,
                end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        else:
            if scan_type == "port":
                result = scanner.port_scan(target)
            elif scan_type == "full":
                result = scanner.full_scan(target)
            elif scan_type == "stealth":
                result = scanner.stealth_scan(target)
            else:
                result = scanner.port_scan(target)

            result.session_id = session_id

    except Exception as e:
        console.print(f"[bold red]Scan error:[/bold red] {e}")
        db.end_session(session_id, 0, 0, 0)
        return

    # Save results
    db.save_scan_result(result)
    for host in result.hosts:
        db.save_host(host)

    db.end_session(
        session_id=session_id,
        packet_count=0,
        total_bytes=0,
        alert_count=0,
    )

    # Display results
    display_scan_results(result)


def run_pcap_analysis(config: dict, db: Database, privacy: PrivacyFilter):
    """
    Mode 3: PCAP Analysis — Load and analyze .pcap capture files.
    """
    filepath = config.get("_pcap_path") or prompt_pcap_path()
    if not filepath:
        return

    loader = PcapLoader()
    display_pcap_loading(filepath)

    try:
        packets = loader.load(filepath)
        stats_snapshot = loader.get_stats()
    except Exception as e:
        console.print(f"[bold red]Error loading PCAP:[/bold red] {e}")
        return

    if not packets:
        console.print("[yellow]No packets found in file.[/yellow]")
        return

    # Run detection retroactively
    rule_engine = RuleEngine(rules_dir=config.get("rules_directory", "rules"))
    anomaly_detector = AnomalyDetector()
    arp_monitor = ArpMonitor()
    detection_pipeline = PacketDetectionPipeline(rule_engine, anomaly_detector, arp_monitor)
    alert_manager = AlertManager(max_alerts=config.get("max_alerts", 100))

    for pkt in packets:
        for alert in detection_pipeline.evaluate(pkt):
            alert_manager.add(alert)

    # Create session record
    session = SessionInfo(
        session_type="pcap_analysis",
        start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        packet_count=len(packets),
        total_bytes=stats_snapshot.total_bytes,
        alert_count=alert_manager.get_count(),
        filter_applied=filepath,
        status="completed",
    )
    session_id = db.create_session(session)
    db.save_packet_summary(session_id, stats_snapshot)

    # Save alerts
    for alert in alert_manager.get_all():
        alert.session_id = session_id
        db.save_alert(alert)

    # Display results
    display_pcap_analysis(packets, stats_snapshot, alert_manager.get_all())


def run_history_viewer(db: Database):
    """
    Mode 4: View History — Browse past sessions, alerts, and discovered hosts.
    """
    while True:
        choice = display_history_menu()

        if choice == "1":
            # Recent sessions
            sessions = db.get_recent_sessions(10)
            display_sessions(sessions)

            if sessions:
                session_id = Prompt.ask(
                    "Enter session ID for details (or press Enter to go back)",
                    default="",
                )
                if session_id.isdigit():
                    session = db.get_session(int(session_id))
                    if session:
                        alerts = db.get_alerts(session_id=int(session_id))
                        display_session_detail(session, alerts)

        elif choice == "2":
            # All alerts
            severity = Prompt.ask(
                "Filter by severity (CRITICAL/HIGH/WARNING/INFO/all)",
                default="all",
            )
            if severity.lower() == "all":
                alerts = db.get_alerts()
            else:
                alerts = db.get_alerts(severity=severity.upper())
            display_alerts_history(alerts)

        elif choice == "3":
            # Discovered hosts
            hosts = db.get_hosts()
            display_hosts_table(hosts)

        elif choice == "4":
            # Search
            query = Prompt.ask("Search (IP address, date, or keyword)")
            sessions = db.search_sessions(query)
            display_sessions(sessions)

        elif choice == "5":
            # Import JSON Data
            filepath = Prompt.ask("Path to JSON export file")
            if os.path.exists(filepath):
                from storage.importer import Importer
                importer = Importer(db)
                if importer.import_json(filepath):
                    console.print(f"\n[bold green]✓ Successfully imported records from {filepath}[/bold green]")
                else:
                    console.print("\n[bold red]Failed to import records.[/bold red]")
            else:
                console.print(f"\n[red]Error: File '{filepath}' not found.[/red]")
            
            console.print()
            Prompt.ask("Press Enter to continue")

        elif choice == "6" or choice == "":
            break


def run_settings(config: dict, privacy: PrivacyFilter):
    """
    Mode 5: Settings — View and modify configuration.
    """
    console.print()
    console.print("[bold]Current Settings[/bold]")
    console.print()

    from rich.table import Table

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Setting", style="white")
    table.add_column("Value", style="green")

    table.add_row("Database Path", config.get("database_path", "sentinel_data.db"))
    table.add_row("Packet Buffer Size", str(config.get("packet_buffer_size", 500)))
    table.add_row("Dashboard FPS", str(config.get("refresh_fps", 4)))
    table.add_row("Default BPF Filter", config.get("default_filter", "") or "(none)")
    table.add_row("Privacy Masking", "ON" if privacy.enabled else "OFF")
    table.add_row("Rules Directory", config.get("rules_directory", "rules"))
    table.add_row("Alert Dedup Window", f"{config.get('dedup_window', 60)}s")
    table.add_row("Max Alerts", str(config.get("max_alerts", 100)))
    table.add_row("Export Directory", config.get("export_directory", "exports"))

    console.print(table)
    console.print()

    # Toggle privacy masking
    if Confirm.ask("Toggle privacy masking?", default=False):
        privacy.enabled = not privacy.enabled
        state = "ON" if privacy.enabled else "OFF"
        console.print(f"[green]Privacy masking: {state}[/green]")

    console.print()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="my-sentinel",
        description="Network Traffic Analyzer & Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sentinel.py                  Interactive menu mode
  python sentinel.py --capture        Jump to live capture
  python sentinel.py --scan 192.168.1.0/24
  python sentinel.py --pcap capture.pcap
  python sentinel.py --mask           Enable privacy masking
        """,
    )

    parser.add_argument(
        "--capture", action="store_true", help="Jump directly to live capture mode"
    )
    parser.add_argument("--scan", type=str, help="Scan a target IP or subnet")
    parser.add_argument("--pcap", type=str, help="Analyze a PCAP file")
    parser.add_argument(
        "--mask", action="store_true", help="Enable IP privacy masking"
    )
    parser.add_argument(
        "--no-admin-check",
        action="store_true",
        help="Skip admin privilege check (some features may fail)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="sentinel_data.db",
        help="SQLite database path (default: sentinel_data.db)",
    )
    parser.add_argument("--version", action="version", version=f"my-sentinel v{APP_VERSION}")

    return parser.parse_args()


def main():
    """Main entry point for my-sentinel."""
    args = parse_args()

    # Load configuration
    config = load_config()

    # Override config with CLI args
    if args.db:
        config["database_path"] = args.db

    # Privacy filter
    privacy = PrivacyFilter(enabled=args.mask)

    # Privilege check
    if not args.no_admin_check:
        check_privileges(require_exit=False)

    # Initialize database
    db = Database(db_path=config["database_path"])

    try:
        # Direct mode from CLI args
        if args.capture:
            console.print(APP_BANNER)
            run_live_capture(config, db, privacy)
            return

        if args.scan:
            console.print(APP_BANNER)
            # Quick scan from CLI
            if not check_nmap_installed():
                return
            scanner = NetworkScanner()
            session = SessionInfo(
                session_type="scan",
                start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                target=args.scan,
                status="active",
            )
            session_id = db.create_session(session)
            display_scan_progress(args.scan, "port")
            result = scanner.port_scan(args.scan)
            result.session_id = session_id
            db.save_scan_result(result)
            for host in result.hosts:
                db.save_host(host)
            db.end_session(session_id, 0, 0, 0)
            display_scan_results(result)
            return

        if args.pcap:
            console.print(APP_BANNER)
            # Override prompt with CLI arg
            config["_pcap_path"] = args.pcap
            run_pcap_analysis(config, db, privacy)
            return

        # Interactive menu mode
        while True:
            console.clear()
            choice = show_main_menu()

            if choice == "1":
                run_live_capture(config, db, privacy)
            elif choice == "2":
                run_network_scan(config, db)
            elif choice == "3":
                run_pcap_analysis(config, db, privacy)
            elif choice == "4":
                run_history_viewer(db)
            elif choice == "5":
                run_settings(config, privacy)
            elif choice == "6":
                console.print()
                console.print("[bold cyan]Goodbye![/bold cyan]")
                break
            else:
                console.print("[yellow]Invalid option. Please select 1-6.[/yellow]")

            if choice != "6":
                console.print()
                Prompt.ask("Press Enter to continue")

    except KeyboardInterrupt:
        console.print()
        console.print("[bold cyan]Interrupted. Goodbye![/bold cyan]")
    finally:
        db.close()


if __name__ == "__main__":
    main()
