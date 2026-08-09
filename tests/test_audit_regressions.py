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

    def test_sniffer_restart_applies_new_filter_and_preserves_callback(self):
        callback_packets = []

        def callback(packet):
            callback_packets.append(packet)

        def fake_sniff(iface=None, filter=None, prn=None, stop_filter=None, store=0):
            if prn:
                prn(Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP())

        with patch("core.sniffer.scapy.sniff", side_effect=fake_sniff):
            sniffer = PacketSniffer()
            sniffer.start(interface="eth-test", callback=callback)
            time.sleep(0.05)
            sniffer.restart_with_filter("tcp port 443")
            time.sleep(0.05)

        self.assertEqual(sniffer.interface, "eth-test")
        self.assertEqual(sniffer.bpf_filter, "tcp port 443")
        self.assertEqual(len(callback_packets), 2)
        self.assertFalse(sniffer.is_running())


if __name__ == "__main__":
    unittest.main()
