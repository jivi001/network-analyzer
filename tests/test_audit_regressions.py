import csv
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap

from core.pcap_loader import PcapLoader
from core.processor import process_packet
from core.sniffer import PacketSniffer
from core.stats import StatsAggregator
from detection.anomaly import AnomalyDetector, shannon_entropy
from detection.arp_monitor import ArpMonitor
from detection.pipeline import PacketDetectionPipeline
from detection.rule_engine import RuleEngine
from storage.database import Database
from storage.exporter import Exporter
from storage.models import AlertInfo, HostInfo, SessionInfo


class AuditRegressionTests(unittest.TestCase):
    def test_entropy_handles_edge_cases(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("a"), 0.0)
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)
        self.assertGreater(shannon_entropy("xn4p9q7r2s8t6uvwmz10ab"), 3.5)

    def test_rule_engine_does_not_alert_on_ordinary_dns_or_first_arp(self):
        engine = RuleEngine("rules")

        dns_packet = process_packet(
            Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
            1,
        )
        arp_packet = process_packet(
            Ether(src="00:11:22:33:44:55") / ARP(op=1, psrc="10.0.0.2", pdst="10.0.0.1", hwsrc="00:11:22:33:44:55"),
            2,
        )

        self.assertEqual([a.rule_name for a in engine.evaluate(dns_packet)], [])
        self.assertEqual([a.rule_name for a in engine.evaluate(arp_packet)], [])

    def test_shared_detection_pipeline_finds_pcap_dns_exfil_and_arp_spoof(self):
        packets = [
            Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
            Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="xq9z8v7w6r5t4y3u2i1opa.example.com")),
            Ether(src="00:11:22:33:44:55") / ARP(op=2, psrc="10.0.0.1", pdst="10.0.0.2", hwsrc="00:11:22:33:44:55"),
            Ether(src="66:77:88:99:aa:bb") / ARP(op=2, psrc="10.0.0.1", pdst="10.0.0.2", hwsrc="66:77:88:99:aa:bb"),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = Path(tmp) / "audit.pcap"
            wrpcap(str(pcap_path), packets)
            decoded = PcapLoader().load(str(pcap_path))

        pipeline = PacketDetectionPipeline(RuleEngine("rules"), AnomalyDetector(), ArpMonitor())
        alerts_by_packet = [pipeline.evaluate(packet) for packet in decoded]
        alerts = [alert for packet_alerts in alerts_by_packet for alert in packet_alerts]

        rule_names = [alert.rule_name for alert in alerts]
        self.assertEqual(alerts_by_packet[0], [])
        self.assertIn("DNS Exfiltration Tunnel", rule_names)
        self.assertIn("ARP Spoofing", rule_names)

    def test_stats_tracks_protocols_bytes_hosts_and_top_talkers(self):
        stats = StatsAggregator()
        packets = [
            process_packet(Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=12345, dport=80, flags="S"), 1),
            process_packet(Ether() / IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=53, dport=53000), 2),
            process_packet(Ether() / ARP(op=1, psrc="10.0.0.4", pdst="10.0.0.1"), 3),
        ]
        for packet in packets:
            stats.update(packet)

        snapshot = stats.get_snapshot()
        self.assertEqual(snapshot.total_packets, 3)
        self.assertEqual(snapshot.protocol_counts["TCP"], 1)
        self.assertEqual(snapshot.protocol_counts["UDP"], 1)
        self.assertEqual(snapshot.protocol_counts["ARP"], 1)
        self.assertEqual(snapshot.unique_hosts_total, 4)
        self.assertEqual(snapshot.total_bytes, sum(p.length for p in packets))
        self.assertTrue(snapshot.top_talkers)

    def test_exporter_creates_valid_csv_and_json(self):
        packet = process_packet(Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=12345, dport=80, flags="S"), 1)
        stats = StatsAggregator()
        stats.update(packet)
        alert = AlertInfo(rule_name="Test", severity="INFO", message="message", src_ip="10.0.0.2")

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "packets.csv"
            json_path = Path(tmp) / "alerts.json"
            exporter = Exporter()
            exporter.export_csv(str(csv_path), [packet], stats.get_snapshot())
            exporter.export_json(str(json_path), [alert], stats.get_snapshot())

            with csv_path.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[0]["protocol"], "TCP")

            data = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(data["alerts"][0]["rule_name"], "Test")
            self.assertEqual(data["stats"]["total_packets"], 1)

    def test_database_persists_sessions_alerts_hosts_across_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "sentinel.db")
            db = Database(db_path)
            session_id = db.create_session(SessionInfo(session_type="capture", start_time="2026-08-09 12:00:00", status="active"))
            db.save_alert(AlertInfo(session_id=session_id, rule_name="Test", severity="HIGH", message="alert"))
            db.save_host(HostInfo(ip_address="10.0.0.2", hostname="host", open_ports=["80/tcp (http)"], services={"80/tcp": "http"}, source="nmap"))
            db.end_session(session_id, packet_count=1, total_bytes=64, alert_count=1)
            db.close()

            reopened = Database(db_path)
            self.assertEqual(reopened.get_recent_sessions(1)[0].id, session_id)
            self.assertEqual(reopened.get_alerts(session_id=session_id)[0].rule_name, "Test")
            self.assertEqual(reopened.get_host_by_ip("10.0.0.2").hostname, "host")
            reopened.close()

    def test_exporter_path_traversal_rejection(self):
        exporter = Exporter()
        with self.assertRaises(ValueError):
            exporter.validate_export_path("../../../etc/passwd", "exports")
        with self.assertRaises(ValueError):
            exporter.validate_export_path("..\\..\\windows\\system32", "exports")

    def test_scanner_target_validation(self):
        from core.scanner import NetworkScanner
        scanner = NetworkScanner.__new__(NetworkScanner)
        scanner.config = {}
        scanner.timeout = 300
        
        self.assertEqual(scanner.validate_target("192.168.1.1"), "192.168.1.1")
        self.assertEqual(scanner.validate_target("10.0.0.0/24"), "10.0.0.0/24")
        self.assertEqual(scanner.validate_target("example.com"), "example.com")
        
        with self.assertRaises(ValueError):
            scanner.validate_target("192.168.1.1; cat /etc/passwd")
        with self.assertRaises(ValueError):
            scanner.validate_target("-sS 192.168.1.1")

    def test_database_recovers_from_corrupted_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "corrupt.db")
            db = Database(db_path)
            c = db.conn.cursor()
            c.execute(
                "INSERT INTO discovered_hosts (ip_address, open_ports, services) VALUES (?, ?, ?)",
                ("10.0.0.99", "{bad_json", "not_a_json_obj")
            )
            db.conn.commit()

            host = db.get_host_by_ip("10.0.0.99")
            self.assertIsNotNone(host)
            self.assertEqual(host.open_ports, [])
            self.assertEqual(host.services, {})
            db.close()

    def test_anomaly_detector_bounds_memory(self):
        detector = AnomalyDetector(max_hosts=5, max_beacon_pairs=5)
        pkt = process_packet(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80), 1)

        # Flood scan state
        for i in range(20):
            pkt.src_ip = f"10.0.0.{i+1}"
            pkt.dst_port = 80 + i
            detector.check_port_scan(pkt)

        self.assertLessEqual(len(detector.scan_state), 5)

        # Flood beacon state
        for i in range(20):
            pkt.src_ip = f"10.0.0.{i+1}"
            pkt.dst_ip = "192.168.1.1"
            detector.check_beaconing(pkt)

        self.assertLessEqual(len(detector.beacon_state), 5)

    def test_bpf_filter_validation(self):
        from sentinel import validate_bpf_filter
        self.assertTrue(validate_bpf_filter(""))
        self.assertTrue(validate_bpf_filter("tcp port 80"))
        self.assertFalse(validate_bpf_filter("invalid !!! bpf filter syntax"))

    def test_config_validation(self):
        from sentinel import _validate_config
        invalid_config = {
            "packet_buffer_size": -50,
            "packet_queue_size": "abc",
            "refresh_fps": 999,
            "database_path": "",
        }
        validated = _validate_config(invalid_config)
        self.assertEqual(validated["packet_buffer_size"], 500)
        self.assertEqual(validated["packet_queue_size"], 10000)
        self.assertEqual(validated["refresh_fps"], 10)
        self.assertTrue(validated["database_path"].endswith("sentinel_data.db"))

    def test_pipeline_exception_isolation(self):
        class BrokenRuleEngine:
            def evaluate(self, pkt):
                raise RuntimeError("Simulated rule engine failure")

        engine = BrokenRuleEngine()
        anomaly = AnomalyDetector()
        arp = ArpMonitor()
        pipeline = PacketDetectionPipeline(engine, anomaly, arp)

        dns_pkt = process_packet(
            Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="xq9z8v7w6r5t4y3u2i1opa.example.com")),
            1,
        )
        alerts = pipeline.evaluate(dns_pkt)
        self.assertTrue(any(a.rule_name == "DNS Exfiltration Tunnel" for a in alerts))

    def test_importer_strict_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "import_test.db")
            db = Database(db_path)
            from storage.importer import Importer
            importer = Importer(db)

            # Test invalid JSON format
            bad_json_path = Path(tmp) / "bad.json"
            bad_json_path.write_text("[1, 2, 3]", encoding="utf-8")
            self.assertFalse(importer.import_json(str(bad_json_path)))

            # Test safe truncation of long strings
            long_alert_path = Path(tmp) / "long.json"
            long_alert_data = {
                "alerts": [
                    {
                        "rule_name": "A" * 500,
                        "message": "B" * 5000,
                        "severity": "CRITICAL",
                        "src_ip": "10.0.0.1",
                    }
                ]
            }
            long_alert_path.write_text(json.dumps(long_alert_data), encoding="utf-8")
            self.assertTrue(importer.import_json(str(long_alert_path)))
            
            alerts = db.get_alerts()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(len(alerts[0].rule_name), 200)
            self.assertEqual(len(alerts[0].message), 1000)
            db.close()


if __name__ == "__main__":
    unittest.main()
