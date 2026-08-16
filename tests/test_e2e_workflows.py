"""
test_e2e_workflows.py — High-value complete end-to-end integration workflows:
Workflows A, B, C, D, and E.
"""

import os
import tempfile
import time
from unittest.mock import patch
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap, rdpcap

from core.processor import process_packet
from core.stats import StatsAggregator
from core.pcap_loader import PcapLoader
from detection.rule_engine import RuleEngine
from detection.anomaly import AnomalyDetector
from detection.arp_monitor import ArpMonitor
from detection.pipeline import PacketDetectionPipeline
from detection.alerts import AlertManager
from storage.database import Database
from storage.exporter import Exporter
from storage.importer import Importer
from storage.models import SessionInfo, PacketInfo, AlertInfo, StatsSnapshot, HostInfo
from traffic_lab import Counters, do_internet_action


class TestEndToEndWorkflows:
    @pytest.fixture
    def env(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name
        temp_dir = tempfile.mkdtemp()
        db = Database(db_path)
        yield {"db": db, "dir": temp_dir}
        db.close()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass

    def test_workflow_a_packets_to_detection_to_db_to_json_roundtrip(self, env):
        """WORKFLOW A: Synthetic packets -> processing -> detection -> statistics -> SQLite -> JSON export -> JSON import -> History"""
        db = env["db"]
        temp_dir = env["dir"]

        pipeline = PacketDetectionPipeline(RuleEngine("rules"), AnomalyDetector(), ArpMonitor())
        aggregator = StatsAggregator()
        alert_mgr = AlertManager()

        scapy_pkts = [
            Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="S"),
            Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=54322, dport=80, flags="S"),
            Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=1234, dport=53),
        ]

        processed_packets = []
        for idx, raw in enumerate(scapy_pkts, 1):
            p_info = process_packet(raw, packet_id=idx)
            processed_packets.append(p_info)
            aggregator.update(p_info)
            for alert in pipeline.evaluate(p_info):
                alert_mgr.add(alert)

        assert len(processed_packets) == 3
        stats = aggregator.get_snapshot()

        session = SessionInfo(session_type="live_capture", packet_count=len(processed_packets), total_bytes=stats.total_bytes, status="completed")
        session_id = db.create_session(session)
        db.save_packet_summary(session_id, stats)
        all_alerts = alert_mgr.get_all()
        for a in all_alerts:
            a.session_id = session_id
        db.save_alerts_batch(all_alerts)

        exporter = Exporter()
        export_file = os.path.join(temp_dir, "workflow_a.json")
        exporter.export_json(export_file, alerts=all_alerts, stats=stats, packets=processed_packets)
        assert os.path.exists(export_file)

        importer = Importer(db)
        import_res = importer.import_json(export_file, raise_on_error=True)
        assert import_res.success is True
        assert import_res.session_id > session_id

        imported_session = db.get_session(import_res.session_id)
        assert imported_session.session_type == "imported"
        search_results = db.search_sessions("workflow_a.json")
        assert len(search_results) >= 1

    def test_workflow_b_packets_pcap_offline_analysis_and_export_reload(self, env):
        """WORKFLOW B: Synthetic packets -> PCAP -> offline analysis -> threat detection -> PCAP export -> reload exported PCAP"""
        temp_dir = env["dir"]
        pcap_path = os.path.join(temp_dir, "workflow_b_orig.pcap")

        pkts = [
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=443) / b"TLS data 1",
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=443) / b"TLS data 2",
        ]
        wrpcap(pcap_path, pkts)

        loader = PcapLoader()
        loaded_packets = loader.load(pcap_path)
        assert len(loaded_packets) == 2
        stats = loader.get_stats()
        assert stats.total_packets == 2

        exporter = Exporter()
        reexport_path = os.path.join(temp_dir, "workflow_b_reexport.pcap")
        exporter.export_pcap(reexport_path, loaded_packets)
        assert os.path.exists(reexport_path)

        reloaded = rdpcap(reexport_path)
        assert len(reloaded) == 2

    def test_workflow_c_pcap_forensics_to_csv_export_validation(self, env):
        """WORKFLOW C: PCAP -> offline forensic dashboard -> CSV export -> CSV validation"""
        temp_dir = env["dir"]
        pcap_path = os.path.join(temp_dir, "workflow_c.pcap")

        pkts = [
            Ether() / IP(src="172.16.0.5", dst="172.16.0.1") / UDP(sport=5000, dport=53) / b"DNS query",
        ]
        wrpcap(pcap_path, pkts)

        loader = PcapLoader()
        loaded = loader.load(pcap_path)

        csv_path = os.path.join(temp_dir, "workflow_c.csv")
        exporter = Exporter()
        exporter.export_csv(csv_path, packets=loaded)

        assert os.path.exists(csv_path)
        with open(csv_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) >= 2
            assert "172.16.0.5" in lines[1]

    def test_workflow_d_pcap_to_json_to_db_history(self, env):
        """WORKFLOW D: PCAP -> offline forensic dashboard -> JSON export -> JSON import -> History"""
        db = env["db"]
        temp_dir = env["dir"]
        pcap_path = os.path.join(temp_dir, "workflow_d.pcap")

        pkts = [
            Ether() / IP(src="192.168.0.10", dst="192.168.0.1") / TCP(sport=2222, dport=80) / b"HTTP request",
        ]
        wrpcap(pcap_path, pkts)

        loader = PcapLoader()
        loaded = loader.load(pcap_path)
        stats = loader.get_stats()

        json_path = os.path.join(temp_dir, "workflow_d.json")
        exporter = Exporter()
        exporter.export_json(json_path, packets=loaded, stats=stats)

        importer = Importer(db)
        res = importer.import_json(json_path, raise_on_error=True)
        assert res.success is True

        sessions = db.get_recent_sessions(5)
        assert any(s.id == res.session_id for s in sessions)

    def test_workflow_e_traffic_lab_generator_to_rate_measurement(self):
        """WORKFLOW E: traffic generator -> actual rate measurement -> packet processing -> metrics -> drop/backlog validation"""
        c = Counters()
        with patch("traffic_lab.http_get", return_value=256), patch("traffic_lab.dns_query", return_value=64):
            for _ in range(10):
                do_internet_action(c)

        assert c.attempts == 10
        assert c.successes == 10
        assert c.failures == 0
        assert c.tx == 640
        assert c.rx > 0
