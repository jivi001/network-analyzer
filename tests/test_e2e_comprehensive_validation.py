import unittest
import os
import sys
import time
import tempfile
import threading
import queue
from datetime import datetime
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR

# Subsystem imports
from storage.models import PacketInfo, AlertInfo, HostInfo, SessionInfo, ScanResult, StatsSnapshot
from storage.database import Database
from storage.exporter import Exporter
from storage.importer import Importer
from core.processor import process_packet
from core.stats import StatsAggregator
from core.sniffer import PacketSniffer, CaptureState
from core.scanner import NetworkScanner
from detection.pipeline import PacketDetectionPipeline
from detection.rule_engine import RuleEngine
from detection.anomaly import AnomalyDetector
from detection.arp_monitor import ArpMonitor
from detection.alerts import AlertManager
from utils.privacy import PrivacyFilter
from utils.constants import SCAN_TYPES, APP_VERSION
from utils.console import console, ScreenState, screen_manager, clear_screen, enter_alt_screen, exit_alt_screen
from sentinel import _validate_config, load_config, validate_bpf_filter, get_absolute_path


class CompleteEndToEndValidationTests(unittest.TestCase):
    """Exhaustive validation test suite covering all subsystems and operational requirements."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_e2e.db")
        self.db = Database(self.db_path)

    def tearDown(self):
        self.db.close()
        # Clean up database and WAL files
        for ext in ["", "-wal", "-shm"]:
            fpath = self.db_path + ext
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception:
                    pass
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass

    # 1. Configuration & Path Resolution
    def test_configuration_validation_and_path_resolution(self):
        bad_config = {
            "packet_buffer_size": -100,
            "packet_queue_size": "not_an_int",
            "refresh_fps": 1000,
            "dedup_window": -5,
            "max_alerts": 0,
            "database_path": "custom_data.db",
            "export_directory": "custom_exports",
            "rules_directory": "custom_rules",
        }
        validated = _validate_config(bad_config)
        self.assertEqual(validated["packet_buffer_size"], 500)
        self.assertEqual(validated["packet_queue_size"], 10000)
        self.assertEqual(validated["refresh_fps"], 10)
        self.assertEqual(validated["dedup_window"], 60)
        self.assertEqual(validated["max_alerts"], 100)
        self.assertTrue(os.path.isabs(validated["database_path"]))
        self.assertTrue(os.path.isabs(validated["export_directory"]))
        self.assertTrue(os.path.isabs(validated["rules_directory"]))

    # 2. BPF Filter Validation & Injection Rejection
    def test_bpf_filter_security_validation(self):
        valid_filters = ["tcp", "udp port 53", "ip host 192.168.1.1", "tcp port 80 or tcp port 443", "arp"]
        for f in valid_filters:
            self.assertTrue(validate_bpf_filter(f), f"Filter '{f}' should be valid")

        malicious_filters = [
            "tcp; rm -rf /",
            "tcp && dir",
            "udp | calc.exe",
            "tcp `whoami`",
            "tcp $(echo bad)",
            "tcp > /dev/null",
            "invalid_protocol_xyz 12345",
        ]
        for f in malicious_filters:
            self.assertFalse(validate_bpf_filter(f), f"Malicious/malformed filter '{f}' must be rejected")

    # 3. Packet Processor Layer Decoding & Info Format
    def test_packet_layer_decoding_comprehensive(self):
        # TCP SYN
        pkt_tcp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="142.250.190.46", ttl=64) / TCP(sport=54321, dport=443, flags="S", seq=1000)
        info_tcp = process_packet(pkt_tcp, 1)
        self.assertIsNotNone(info_tcp)
        self.assertEqual(info_tcp.protocol, "TCP")
        self.assertEqual(info_tcp.service, "HTTPS")
        self.assertIn("SYN", info_tcp.flags)
        self.assertEqual(info_tcp.src_ip, "192.168.1.10")
        self.assertEqual(info_tcp.dst_ip, "142.250.190.46")

        # UDP DNS Query
        pkt_dns = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
        info_dns = process_packet(pkt_dns, 2)
        self.assertIsNotNone(info_dns)
        self.assertEqual(info_dns.protocol, "DNS")
        self.assertEqual(info_dns.service, "DNS")
        self.assertEqual(info_dns.dns_query, "google.com")

        # ARP Request
        pkt_arp = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.100", hwsrc="00:11:22:33:44:55", hwdst="00:00:00:00:00:00")
        info_arp = process_packet(pkt_arp, 3)
        self.assertIsNotNone(info_arp)
        self.assertEqual(info_arp.protocol, "ARP")
        self.assertEqual(info_arp.src_ip, "192.168.1.1")
        self.assertEqual(info_arp.dst_ip, "192.168.1.100")

        # ICMP Echo Request
        pkt_icmp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(type=8, code=0)
        info_icmp = process_packet(pkt_icmp, 4)
        self.assertIsNotNone(info_icmp)
        self.assertEqual(info_icmp.protocol, "ICMP")
        self.assertIn("Type=8", info_icmp.info)

    # 4. Decoupled Thread Worker & Drop Accounting
    def test_decoupled_packet_worker_lifecycle(self):
        packet_queue = queue.Queue(maxsize=100)
        stats = StatsAggregator()
        rule_engine = RuleEngine(rules_dir="rules")
        anomaly = AnomalyDetector()
        arp = ArpMonitor()
        pipeline = PacketDetectionPipeline(rule_engine, anomaly, arp)
        alert_manager = AlertManager()

        captured = [0]
        enqueued = [0]
        processed = [0]
        dropped = [0]

        running = threading.Event()
        running.set()

        def worker():
            while running.is_set() or not packet_queue.empty():
                try:
                    pkt = packet_queue.get(timeout=0.01)
                except queue.Empty:
                    continue
                processed[0] += 1
                info = process_packet(pkt, processed[0])
                if info:
                    stats.update(info)
                    for a in pipeline.evaluate(info):
                        alert_manager.add(a)
                packet_queue.task_done()

        t = threading.Thread(target=worker, daemon=True)
        t.start()

        # Produce 150 packets into 100 maxsize queue
        sample = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=1234, dport=80)
        for _ in range(150):
            captured[0] += 1
            try:
                packet_queue.put_nowait(sample)
                enqueued[0] += 1
            except queue.Full:
                dropped[0] += 1

        running.clear()
        t.join(timeout=3.0)

        self.assertEqual(captured[0], 150)
        self.assertEqual(enqueued[0] + dropped[0], 150)
        self.assertEqual(processed[0], enqueued[0])
        self.assertEqual(stats.get_snapshot().total_packets, enqueued[0])

    # 5. Sniffer Repeated Start/Stop Thread Lifecycle
    def test_sniffer_repeated_start_stop_50_cycles(self):
        sniffer = PacketSniffer()
        self.assertEqual(sniffer.state, CaptureState.IDLE)

        # Execute 50 rapid start/stop cycles
        for i in range(50):
            sniffer.start(callback=lambda p: None)
            time.sleep(0.01)
            self.assertTrue(sniffer.is_running())
            sniffer.stop()
            time.sleep(0.01)
            self.assertFalse(sniffer.is_running())
            self.assertEqual(sniffer.state, CaptureState.STOPPED)

    # 6. Detection Pipeline & Failure Isolation
    def test_detection_pipeline_failure_isolation(self):
        class FaultyRuleEngine:
            def evaluate(self, pkt):
                raise RuntimeError("Faulty rule engine injected exception")

        pipeline = PacketDetectionPipeline(FaultyRuleEngine(), AnomalyDetector(), ArpMonitor())
        pkt_info = PacketInfo(
            id=1,
            timestamp=time.time(),
            timestamp_str="12:00:00.000",
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            protocol="UDP",
            src_port=53000,
            dst_port=53,
            dns_query="test.com",
        )
        # Must not raise exception even when rule engine throws
        alerts = pipeline.evaluate(pkt_info)
        self.assertIsInstance(alerts, list)

    # 7. Nmap Profile Allowlist and Argument Enforcement
    def test_nmap_profiles_and_validation(self):
        scanner = NetworkScanner()
        profiles = [
            "discovery", "fast_discovery", "top_ports", "service", "version",
            "os_detection", "comprehensive", "udp_top", "tcp_connect",
            "aggressive", "ipv6_discovery", "stealth"
        ]
        for p in profiles:
            args = scanner._get_scan_args(p)
            self.assertIsInstance(args, str)
            self.assertGreater(len(args), 0)

        # Invalid target rejections
        invalid_targets = ["", "   ", "192.168.1.1; rm -rf /", "192.168.1.1 & dir", "invalid_host_$$$"]
        for bad_tgt in invalid_targets:
            with self.assertRaises(ValueError):
                scanner.scan(bad_tgt, "top_ports")

    # 8. Database Transactions, Schema, and Recovery
    def test_database_e2e_persistence_and_queries(self):
        session = SessionInfo(
            session_type="capture",
            start_time="2026-08-14 12:00:00",
            interface="eth0",
            filter_applied="tcp",
            status="completed",
        )
        session_id = self.db.create_session(session)
        self.assertGreater(session_id, 0)

        # Save batch alerts
        alerts = [
            AlertInfo(session_id=session_id, timestamp=time.time(), timestamp_str="12:00:01", rule_name="Test Rule 1", severity="HIGH", message="Test Msg 1"),
            AlertInfo(session_id=session_id, timestamp=time.time(), timestamp_str="12:00:02", rule_name="Test Rule 2", severity="CRITICAL", message="Test Msg 2"),
        ]
        self.db.save_alerts_batch(alerts)
        fetched_alerts = self.db.get_alerts(session_id=session_id)
        self.assertEqual(len(fetched_alerts), 2)

        # Save hosts
        host = HostInfo(ip_address="192.168.1.50", mac_address="00:11:22:33:44:55", hostname="testhost", os_guess="Linux")
        self.db.save_host(host)
        hosts = self.db.get_hosts()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip_address, "192.168.1.50")

        # Save scan result
        scan_res = ScanResult(session_id=session_id, target="192.168.1.0/24", scan_type="discovery", scan_args="-sn", hosts_found=1, duration_sec=1.5, hosts=[host])
        self.db.save_scan_result(scan_res)

        # End session
        self.db.end_session(session_id, packet_count=1000, total_bytes=500000, alert_count=2)
        saved_session = self.db.get_session(session_id)
        self.assertEqual(saved_session.packet_count, 1000)
        self.assertEqual(saved_session.alert_count, 2)

    # 9. Exporter & Importer Security & Validation
    def test_exporter_importer_path_traversal_and_validation(self):
        exporter = Exporter()
        export_dir = os.path.join(self.temp_dir, "exports")
        os.makedirs(export_dir, exist_ok=True)

        # Valid export path
        valid_path = exporter.validate_export_path("test_export.json", export_dir)
        self.assertTrue(valid_path.startswith(os.path.abspath(export_dir)))

        # Path traversal attack
        traversal_attempts = ["../attack.json", "../../etc/passwd", "..\\..\\windows\\system32\\calc.exe"]
        for bad_p in traversal_attempts:
            with self.assertRaises(ValueError):
                exporter.validate_export_path(bad_p, export_dir)

        # Export JSON and re-import
        alerts = [AlertInfo(timestamp=time.time(), timestamp_str="12:00:00", rule_name="Rule A", severity="INFO", message="Msg A")]
        stats = StatsSnapshot(total_packets=100, total_bytes=50000)
        exporter.export_json(valid_path, alerts, stats)

        importer = Importer(self.db)
        success = importer.import_json(valid_path)
        self.assertTrue(success)

        # Malformed JSON import rejection
        bad_json_file = os.path.join(self.temp_dir, "corrupt.json")
        with open(bad_json_file, "w", encoding="utf-8") as f:
            f.write("{ invalid json content ...")
        self.assertFalse(importer.import_json(bad_json_file))


if __name__ == "__main__":
    unittest.main()
