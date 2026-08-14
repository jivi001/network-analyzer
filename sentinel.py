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
from queue import Empty, Full, Queue

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

from rich.live import Live
from rich.prompt import Prompt, Confirm

from utils.constants import APP_BANNER, APP_VERSION, APP_NAME, DASHBOARD_REFRESH_MS
from utils.console import (
    console,
    enter_alt_screen,
    exit_alt_screen,
    clear_screen,
    ScreenState,
    screen_manager,
)
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


import logging
import shutil
import tempfile

logger = logging.getLogger(__name__)


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def get_absolute_path(path_str: str) -> str:
    """Resolve a relative path against PROJECT_ROOT."""
    if not path_str:
        return path_str
    if os.path.isabs(path_str):
        return path_str
    return os.path.abspath(os.path.join(PROJECT_ROOT, path_str))


def _validate_config(config: dict) -> dict:
    """Validate configuration bounds and resolve paths."""
    validated = config.copy()

    def _check_int(key: str, min_val: int, max_val: int, default_val: int):
        val = validated.get(key, default_val)
        if not isinstance(val, int) or isinstance(val, bool):
            try:
                val = int(val)
            except (ValueError, TypeError):
                logger.warning(f"Config '{key}' invalid. Resetting to {default_val}.")
                val = default_val
        if val < min_val or val > max_val:
            logger.warning(f"Config '{key}' value {val} out of range [{min_val}, {max_val}]. Resetting to {default_val}.")
            val = default_val
        validated[key] = val

    _check_int("packet_buffer_size", 10, 10000, 500)
    _check_int("packet_queue_size", 100, 100000, 10000)
    _check_int("refresh_fps", 1, 30, 10)
    _check_int("dedup_window", 1, 3600, 60)
    _check_int("max_alerts", 10, 100000, 100)

    db_p = validated.get("database_path")
    if not isinstance(db_p, str) or not db_p.strip():
        db_p = "sentinel_data.db"
    validated["database_path"] = get_absolute_path(db_p)

    exp_d = validated.get("export_directory")
    if not isinstance(exp_d, str) or not exp_d.strip():
        exp_d = "exports"
    validated["export_directory"] = get_absolute_path(exp_d)

    rules_d = validated.get("rules_directory")
    if not isinstance(rules_d, str) or not rules_d.strip():
        rules_d = "rules"
    validated["rules_directory"] = get_absolute_path(rules_d)

    return validated


def load_config(config_path_override: Optional[str] = None) -> dict:
    """Load configuration from config.yaml if available, otherwise use defaults."""
    config = {
        "database_path": get_absolute_path("sentinel_data.db"),
        "packet_buffer_size": 500,
        "packet_queue_size": 10000,
        "refresh_fps": 10,
        "default_filter": "",
        "privacy_mask": False,
        "rules_directory": get_absolute_path("rules"),
        "dedup_window": 60,
        "max_alerts": 100,
        "export_directory": get_absolute_path("exports"),
    }

    try:
        import yaml

        config_path = (
            get_absolute_path(config_path_override)
            if config_path_override
            else get_absolute_path("config.yaml")
        )
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                yaml_config = yaml.safe_load(f)

            if isinstance(yaml_config, dict):
                # Flatten nested config safely
                for section_name, section in yaml_config.items():
                    if isinstance(section, dict):
                        config.update(section)
                    else:
                        config[section_name] = section
    except ImportError:
        logger.warning("PyYAML not installed, using default configuration.")
    except Exception as e:
        logger.warning(f"Error loading config.yaml: {e}. Using defaults.")

    return _validate_config(config)


def validate_bpf_filter(bpf_filter: str) -> bool:
    """Validate BPF filter syntax and tokens."""
    if not bpf_filter or not bpf_filter.strip():
        return True

    filter_str = bpf_filter.strip()

    # Check parenthetical balance
    if filter_str.count("(") != filter_str.count(")"):
        logger.error(f"BPF filter validation error: Unbalanced parentheses in '{filter_str}'")
        return False

    # Check for illegal command injection characters
    import re
    if re.search(r"[;`$><|]", filter_str):
        logger.error(f"BPF filter validation error: Illegal character in '{filter_str}'")
        return False

    allowed_keywords = {
        "tcp", "udp", "icmp", "ip", "ip6", "arp", "rarp", "ether", "wlan", "vlan",
        "host", "net", "port", "portrange", "src", "dst", "proto",
        "and", "or", "not", "gateway", "mask", "less", "greater", "broadcast", "multicast",
    }

    tokens = re.findall(r"[a-zA-Z0-9.\-/:]+", filter_str)
    for token in tokens:
        token_lower = token.lower()
        if token_lower in allowed_keywords:
            continue
        if re.match(r"^\d+$", token):
            continue
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", token):
            continue
        if re.match(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$", token):
            continue
        logger.error(f"BPF filter validation error: Invalid BPF token '{token}' in '{filter_str}'")
        return False

    return True


def run_live_capture(config: dict, db: Database, privacy: PrivacyFilter):
    """
    Mode 1: Live Capture — Real-time packet sniffing with TUI dashboard.
    """
    settings = prompt_capture_settings()
    if settings is None:
        return

    interface = settings.get("interface", "").strip()
    target_ip = settings.get("target_ip", "").strip()
    bpf_filter = settings.get("bpf_filter", config.get("default_filter", "")).strip()

    # Validate target IP if specified
    if target_ip:
        import ipaddress
        try:
            ipaddress.ip_address(target_ip)
            ip_filter = f"host {target_ip}"
            bpf_filter = f"({bpf_filter}) and {ip_filter}" if bpf_filter else ip_filter
        except ValueError:
            console.print(f"[bold red]Error:[/bold red] Invalid target IP address '{target_ip}'.")
            return

    # Validate final BPF filter
    if bpf_filter and not validate_bpf_filter(bpf_filter):
        console.print(f"[bold red]Error:[/bold red] Invalid BPF filter syntax '{bpf_filter}'.")
        return

    # Setup components
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
    packet_queue = Queue(maxsize=config.get("packet_queue_size", 5000))
    raw_packets = []
    packet_counter = [0]  # Mutable counter for closure
    dropped_packets = [0]
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
        """Capture callback: keep sniffer thread non-blocking."""
        try:
            packet_queue.put_nowait(raw_pkt)
        except Full:
            dropped_packets[0] += 1

    def process_pending_packets(max_packets: int = 250):
        """Drain queued capture packets into stats, detection, and display buffers."""
        processed = 0
        while processed < max_packets:
            try:
                raw_pkt = packet_queue.get_nowait()
            except Empty:
                break

            with lock:
                packet_counter[0] += 1
                pkt_info = process_packet(raw_pkt, packet_counter[0])

                if pkt_info:
                    stats.update(pkt_info)

                    for alert in detection_pipeline.evaluate(pkt_info):
                        alert.session_id = session_id
                        if alert_manager.add(alert):
                            db.save_alert(alert)

                    packet_buffer.append(pkt_info)
                    raw_packets.append(raw_pkt)

            packet_queue.task_done()
            processed += 1

        return processed

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

        refresh_fps = config.get("refresh_fps", 10)
        refresh_interval = 1.0 / refresh_fps
        paused = False
        recent_latencies: deque = deque(maxlen=10)

        clear_screen()
        with Live(
            dashboard.get_renderable(),
            console=console,
            refresh_per_second=refresh_fps,
            transient=True,
        ) as live:
            while sniffer.is_running():
                try:
                    if not paused:
                        process_pending_packets()
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
                                    new_filter = Prompt.ask("BPF Filter (blank to clear)", default="").strip()
                                    if validate_bpf_filter(new_filter):
                                        bpf_filter = new_filter
                                        sniffer.restart_with_filter(bpf_filter if bpf_filter else None)
                                    else:
                                        console.print(f"[bold red]Filter change failed:[/bold red] Invalid BPF syntax '{new_filter}'")
                                except Exception as e:
                                    from rich.markup import escape
                                    console.print(f"[bold red]Filter change failed:[/bold red] {escape(str(e))}")
                                finally:
                                    live.start(refresh=True)
                            elif key == 'e':
                                live.stop()
                                exporter = Exporter()
                                export_dir = config.get("export_directory", "exports")
                                filename = exporter.generate_filename("capture", "json")
                                try:
                                    filepath = exporter.validate_export_path(filename, export_dir)
                                    exporter.export_json(
                                        filepath,
                                        alert_manager.get_all(),
                                        stats.get_snapshot(),
                                    )
                                    console.print(f"[green]Exported to:[/green] {filepath}")
                                except Exception as e:
                                    from rich.markup import escape
                                    console.print(f"[bold red]Export failed:[/bold red] {escape(str(e))}")
                                finally:
                                    live.start(refresh=True)

                    time.sleep(refresh_interval)
                except KeyboardInterrupt:
                    break

    except KeyboardInterrupt:
        pass
    except Exception as e:
        from rich.markup import escape
        console.print(f"[bold red]Error during capture:[/bold red] {escape(str(e))}")
    finally:
        process_pending_packets(max_packets=packet_queue.qsize())
        sniffer.stop()

        # 2. Stop new enqueue and wait for processor worker to drain remaining packets
        processing_running.clear()
        processor_thread.join(timeout=3.0)

        # 3. Flush alert batch
        flush_alert_batch()

        # 4. Flush & close PCAP writer
        if pcap_writer:
            try:
                pcap_writer.close()
            except Exception as e:
                logger.error(f"Error closing PCAP writer: {e}")

        # 5. Save session summary
        snapshot = stats.get_snapshot()
        db.end_session(
            session_id=session_id,
            packet_count=snapshot.total_packets,
            total_bytes=snapshot.total_bytes,
            alert_count=alert_manager.get_count(),
        )
        db.save_packet_summary(session_id, snapshot)

        # 6. Stop workers
        stats.stop_rate_calculator()

    console.print()
    console.print(f"[bold green]Capture stopped.[/bold green]")
    console.print(f"  Packets: {snapshot.total_packets:,} | Bytes: {snapshot.total_bytes:,} | Alerts: {alert_manager.get_count()}")
    if dropped_packets[0]:
        console.print(f"  Dropped by application queue: {dropped_packets[0]:,}")
    console.print()

    # Offer export
    if snapshot.total_packets > 0 and Confirm.ask("Export capture data?", default=False):
        export_settings = prompt_export_settings()
        if export_settings:
            exporter = Exporter()
            export_dir = config.get("export_directory", "exports")

            fmt = export_settings.get("format", "csv").lower()
            default_fn = exporter.generate_filename("capture", fmt)
            user_fn = export_settings.get("filename", "").strip() or default_fn

            try:
                filepath = exporter.validate_export_path(user_fn, export_dir)

                if fmt == "csv":
                    exporter.export_csv(filepath, list(packet_buffer), snapshot)
                elif fmt == "pcap":
                    if os.path.exists(temp_pcap_path) and os.path.getsize(temp_pcap_path) > 0:
                        shutil.copyfile(temp_pcap_path, filepath)
                    else:
                        raise RuntimeError("No raw PCAP data available for export.")
                elif fmt == "json":
                    exporter.export_json(filepath, alert_manager.get_all(), snapshot)
                else:
                    raise ValueError(f"Unsupported export format: {fmt}")
                console.print(f"[green]Exported to:[/green] {filepath}")
            except Exception as e:
                from rich.markup import escape
                console.print(f"[bold red]Export failed:[/bold red] {escape(str(e))}")

    # 7. Clean up temporary PCAP file
    if os.path.exists(temp_pcap_path):
        try:
            os.remove(temp_pcap_path)
        except Exception as e:
            logger.warning(f"Failed to remove temp PCAP file {temp_pcap_path}: {e}")


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

    display_scan_progress(target, scan_type, scanner._get_scan_args(scan_type))

    try:
        result = scanner.scan(target, scan_type)
        result.session_id = session_id
    except Exception as e:
        from rich.markup import escape
        console.print(f"[bold red]Scan error:[/bold red] {escape(str(e))}")
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
    console.print()
    Prompt.ask("Press Enter to return to main menu", default="")


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
        from rich.markup import escape
        console.print(f"[bold red]Error loading PCAP:[/bold red] {escape(str(e))}")
        return

    if not packets:
        console.print("[yellow]No packets found in file.[/yellow]")
        Prompt.ask("Press Enter to return to main menu", default="")
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
    console.print()
    Prompt.ask("Press Enter to return to main menu", default="")


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
                Prompt.ask("Press Enter to continue", default="")
            else:
                Prompt.ask("Press Enter to continue", default="")

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
            Prompt.ask("Press Enter to continue", default="")

        elif choice == "3":
            # Discovered hosts
            hosts = db.get_hosts()
            display_hosts_table(hosts)
            Prompt.ask("Press Enter to continue", default="")

        elif choice == "4":
            # Search
            query = Prompt.ask("Search (IP address, date, or keyword)")
            sessions = db.search_sessions(query)
            display_sessions(sessions)
            Prompt.ask("Press Enter to continue", default="")

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
            Prompt.ask("Press Enter to return to history menu", default="")

        elif choice == "6" or choice == "":
            break


def run_settings(config: dict, privacy: PrivacyFilter):
    """
    Mode 5: Settings — View and modify configuration.
    """
    screen_manager.set_state(ScreenState.TASK_CONFIG)
    console.print("[bold cyan]Current Settings[/bold cyan]")
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
    Prompt.ask("Press Enter to return to main menu", default="")


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
    parser.add_argument("--scan", type=str, help="Scan a target IP, subnet, or hostname")
    parser.add_argument(
        "--profile",
        "--scan-profile",
        type=str,
        default="top_ports",
        help="Scan profile for --scan (default: top_ports)",
    )
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
        "--config",
        type=str,
        help="Path to custom config.yaml file",
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
    """Main entry point for my-sentinel with state-driven terminal lifecycle."""
    args = parse_args()

    # Load configuration
    config = load_config(config_path_override=args.config)

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

    # 1. Switch to terminal's alternate screen buffer on startup
    enter_alt_screen()

    try:
        # Direct mode from CLI args
        if args.capture:
            screen_manager.set_state(ScreenState.TASK_RUNNING)
            console.print(APP_BANNER)
            run_live_capture(config, db, privacy)
            return

        if args.scan:
            screen_manager.set_state(ScreenState.TASK_RUNNING)
            console.print(APP_BANNER)
            if not check_nmap_installed():
                return
            scanner = NetworkScanner()
            scan_type = args.profile or "top_ports"
            session = SessionInfo(
                session_type="scan",
                start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                target=args.scan,
                status="active",
            )
            session_id = db.create_session(session)
            display_scan_progress(args.scan, scan_type, scanner._get_scan_args(scan_type))
            result = scanner.scan(args.scan, scan_type)
            result.session_id = session_id
            db.save_scan_result(result)
            for host in result.hosts:
                db.save_host(host)
            db.end_session(session_id, 0, 0, 0)
            display_scan_results(result)
            return

        if args.pcap:
            screen_manager.set_state(ScreenState.TASK_RUNNING)
            console.print(APP_BANNER)
            # Override prompt with CLI arg
            config["_pcap_path"] = args.pcap
            run_pcap_analysis(config, db, privacy)
            return

        # Interactive menu mode
        while True:
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
                screen_manager.set_state(ScreenState.EXIT)
                console.print()
                console.print("[bold cyan]Goodbye![/bold cyan]")
                break
            else:
                console.print("[yellow]Invalid option. Please select 1-6.[/yellow]")

    except KeyboardInterrupt:
        screen_manager.set_state(ScreenState.EXIT)
        console.print()
        console.print("[bold cyan]Interrupted. Goodbye![/bold cyan]")
    finally:
        db.close()
        # Guarantee restoration of standard screen buffer and cursor visibility
        exit_alt_screen()


if __name__ == "__main__":
    main()
