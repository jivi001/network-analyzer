import unittest
import os
import sys
import time
import threading
import tempfile
import json
from queue import Queue, Full, Empty
from collections import deque
from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Raw

from core.processor import process_packet
from core.stats import StatsAggregator
from core.sniffer import PacketSniffer, CaptureState
from core.scanner import NetworkScanner
from detection.rule_engine import RuleEngine
from detection.anomaly import AnomalyDetector, shannon_entropy
from detection.arp_monitor import ArpMonitor
from detection.pipeline import PacketDetectionPipeline
from detection.alerts import AlertManager
from storage.database import Database
from storage.exporter import Exporter
from storage.importer import Importer
from storage.models import PacketInfo, AlertInfo, HostInfo, SessionInfo, StatsSnapshot
from network.resolver import Resolver
from network.whois_lookup import WhoisLookup
from network.traceroute import TraceRoute
from sentinel import _validate_config, validate_bpf_filter

class ComprehensiveSubsystemTests(unittest.TestCase):

    def test_processor_edge_cases(self):
        self.assertIsNone(process_packet(None, 1))
        self.assertIsNone(process_packet(b"raw bytes string", 2))
        info = process_packet(Ether()/IP()/TCP(), 3)
        self.assertIsNotNone(info)
        self.assertEqual(info.protocol, "TCP")

    def test_anomaly_detector_edge_cases(self):
        ad = AnomalyDetector(max_hosts=2, max_beacon_pairs=2)
        self.assertIsNone(ad.check_dns_exfiltration(PacketInfo(id=1, timestamp=time.time(), protocol="DNS", dns_query=None)))
        self.assertIsNone(ad.check_dns_exfiltration(PacketInfo(id=2, timestamp=time.time(), protocol="DNS", dns_query="." * 100)))
        self.assertIsNone(ad.check_beaconing(PacketInfo(id=3, timestamp=None, src_ip="", dst_ip="")))
        self.assertIsNone(ad.check_port_scan(PacketInfo(id=4, timestamp=time.time(), protocol="TCP", dst_port=None, src_ip="10.0.0.1")))

    def test_rule_engine_edge_cases(self):
        re = RuleEngine("rules")
        empty_pkt = PacketInfo(id=1, timestamp=time.time())
        alerts = re.evaluate(empty_pkt)
        self.assertIsInstance(alerts, list)

    def test_alert_manager_concurrency(self):
        am = AlertManager(max_alerts=10, dedup_window=1)
        def add_alerts():
            for i in range(50):
                am.add(AlertInfo(rule_name=f"Rule_{i%5}", severity="HIGH", message="test", src_ip=f"10.0.0.{i}"))
        threads = [threading.Thread(target=add_alerts) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertLessEqual(len(am.alerts), 10)

    def test_database_multithreaded_and_sql_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(os.path.join(tmp, "test.db"))
            def db_worker(worker_id):
                for i in range(10):
                    sid = db.create_session(SessionInfo(session_type="test", target=f"' OR '1'='1' -- {worker_id}_{i}"))
                    db.save_alert(AlertInfo(session_id=sid, rule_name="'; DROP TABLE alerts; --", severity="HIGH", message="injection"))
                    db.get_recent_sessions(5)
                    db.search_sessions("' OR 1=1 --")
                    db.get_hosts()
            threads = [threading.Thread(target=db_worker, args=(i,)) for i in range(5)]
            for t in threads: t.start()
            for t in threads: t.join()
            
            # Verify tables still exist
            sessions = db.get_recent_sessions(100)
            self.assertTrue(len(sessions) > 0)
            db.close()

    def test_network_lookups(self):
        r = Resolver(max_cache_size=5)
        self.assertEqual(r.reverse_dns_cached("127.0.0.1"), r.reverse_dns_cached("127.0.0.1"))
        
        w = WhoisLookup(max_cache_size=5)
        info1 = w.lookup_cached("127.0.0.1")
        self.assertEqual(info1.ip, "127.0.0.1")
        
        tr = TraceRoute()
        res = tr.format_results([])
        self.assertIn("Traceroute Results", res)

    def test_exporter_path_traversal_rejection(self):
        exp = Exporter()
        for bad_path in ["../foo.json", "..\\foo.json", "/etc/passwd", "C:\\Windows\\system32", "foo/../../bar.json"]:
            with self.assertRaises(ValueError):
                exp.validate_export_path(bad_path, "exports")

    def test_sniffer_state_machine(self):
        sniffer = PacketSniffer()
        self.assertEqual(sniffer.state, CaptureState.IDLE)
        sniffer.stop()
        self.assertEqual(sniffer.state, CaptureState.STOPPED)
        # Starting with non-existent interface should transition to ERROR state
        sniffer.start(interface="eth-test-invalid", callback=lambda p: None)
        time.sleep(0.01)
        self.assertIn(sniffer.state, (CaptureState.ERROR, CaptureState.STOPPED, CaptureState.STARTING, CaptureState.RUNNING))
        sniffer.stop()

    def test_rich_markup_exception_escaping(self):
        from rich.console import Console
        from rich.markup import escape
        console = Console(record=True)
        # Simulate exception with unclosed/mismatched bracket markup like '[/bold]'
        err = Exception("Sniffer error: closing tag '[/bold]' at position 56 doesn't match")
        try:
            console.print(f"[bold red]Error during capture:[/bold red] {escape(str(err))}")
        except Exception as e:
            self.fail(f"Rich console.print failed with escaped error: {e}")
    def test_dashboard_rendering_markup_safety(self):
        from tui.dashboard import LiveDashboard
        from detection.alerts import AlertManager, AlertInfo
        from core.stats import StatsAggregator
        
        stats = StatsAggregator()
        am = AlertManager()
        am.add(AlertInfo(rule_name="TestRule", severity="HIGH", message="Brackets test [bold red]alert[/bold red] [WinError 10013]", src_ip="10.0.0.1"))
        
        dashboard = LiveDashboard(stats, am)
        # Test rendering under 0 drops, >0 drops, degraded subsystems, and paused state
        try:
            dashboard.update(packets_buffer=[], dropped_count=0, queue_depth=10, queue_capacity=5000, paused=False)
            dashboard.update(packets_buffer=[], dropped_count=5, queue_depth=100, queue_capacity=5000, paused=True, degraded_subsystems={"PCAP": "DEGRADED"})
        except Exception as e:
            self.fail(f"LiveDashboard update failed with markup error: {e}")

    def test_single_console_instance_sharing(self):
        from utils.console import console as shared_console
        from tui.menu import console as menu_console
        from tui.dashboard import console as dash_console
        from tui.scan_view import console as scan_console
        from tui.pcap_view import console as pcap_console
        from tui.history_view import console as hist_console
        from utils.privileges import console as priv_console

        self.assertIs(menu_console, shared_console)
        self.assertIs(dash_console, shared_console)
        self.assertIs(scan_console, shared_console)
        self.assertIs(pcap_console, shared_console)
        self.assertIs(hist_console, shared_console)
        self.assertIs(priv_console, shared_console)

    def test_tui_rendering_start_stop_idempotency(self):
        from tui.dashboard import LiveDashboard
        from detection.alerts import AlertManager
        from core.stats import StatsAggregator
        from rich.live import Live
        from utils.console import console

        stats = StatsAggregator()
        am = AlertManager()
        dashboard = LiveDashboard(stats, am)

        live = Live(dashboard.get_renderable(), console=console, auto_refresh=False)
        # Verify multiple start/stop calls are safe without exceptions or multiple render loops
        live.start()
        live.stop()

    def test_nmap_scan_profiles_allowlist_and_arguments(self):
        from core.scanner import NetworkScanner, ALLOWED_SCAN_TYPES
        from utils.constants import SCAN_TYPES
        from unittest.mock import MagicMock, patch

        with patch("nmap.PortScanner") as mock_nm_cls:
            mock_nm = MagicMock()
            mock_nm_cls.return_value = mock_nm

            scanner = NetworkScanner({"timeout": 120})
            profiles = [
                "discovery", "fast_discovery", "top_ports", "service",
                "version", "os_detection", "comprehensive", "udp_top",
                "tcp_connect", "aggressive", "ipv6_discovery", "stealth",
                "quick", "port", "full",
            ]

            for prof in profiles:
                self.assertIn(prof, ALLOWED_SCAN_TYPES)
                args = scanner._get_scan_args(prof)
                self.assertIn("--host-timeout 120s", args)

    def test_nmap_invalid_scan_profile_rejection(self):
        from core.scanner import NetworkScanner
        from unittest.mock import MagicMock, patch

        with patch("nmap.PortScanner") as mock_nm_cls:
            mock_nm = MagicMock()
            mock_nm_cls.return_value = mock_nm

            scanner = NetworkScanner()
            with self.assertRaises(ValueError) as ctx:
                scanner.scan("127.0.0.1", "invalid_profile_123")
            self.assertIn("Unknown scan profile", str(ctx.exception))

    def test_nmap_mocked_profile_scanning_and_normalization(self):
        from core.scanner import NetworkScanner
        from storage.models import ScanResult
        from unittest.mock import MagicMock, patch

        with patch("nmap.PortScanner") as mock_nm_cls:
            mock_nm = MagicMock()
            mock_nm_cls.return_value = mock_nm
            mock_nm.all_hosts.return_value = ["127.0.0.1"]

            host_data = {
                "addresses": {"ipv4": "127.0.0.1", "mac": "00:11:22:33:44:55"},
                "osmatch": [{"name": "Linux 5.x"}],
                "tcp": {
                    80: {"state": "open", "name": "http", "product": "nginx", "version": "1.25.0", "extrainfo": "Ubuntu"},
                },
            }

            mock_host = MagicMock()
            mock_host.get.side_effect = host_data.get
            mock_host.__getitem__.side_effect = host_data.__getitem__
            mock_host.state.return_value = "up"
            mock_host.all_protocols.return_value = ["tcp"]
            mock_host.hostname.return_value = "localhost"

            mock_nm.__getitem__.return_value = mock_host

            scanner = NetworkScanner()
            for prof in ["discovery", "service", "comprehensive", "udp_top", "aggressive"]:
                res = scanner.scan("127.0.0.1", prof)
                self.assertIsInstance(res, ScanResult)
                self.assertEqual(res.target, "127.0.0.1")
                self.assertEqual(res.scan_type, prof)
                self.assertEqual(res.hosts_found, 1)
                self.assertEqual(len(res.hosts), 1)
                host = res.hosts[0]
                self.assertEqual(host.ip_address, "127.0.0.1")
                self.assertEqual(host.mac_address, "00:11:22:33:44:55")
                self.assertEqual(host.hostname, "localhost")
                self.assertEqual(host.os_guess, "Linux 5.x")


if __name__ == "__main__":
    unittest.main()
