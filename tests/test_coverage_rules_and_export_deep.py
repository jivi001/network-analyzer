"""
test_coverage_rules_and_export_deep.py — Deep branch coverage tests for detection/rule_engine.py
and storage/exporter.py:
Cleartext condition, high port condition, MAC change condition, rule reloading,
alerts-only CSV exports, and PCAP raw packet layer extraction.
"""

import os
import tempfile
import pytest
from scapy.layers.inet import IP, TCP
from storage.models import PacketInfo, AlertInfo, DetectionRule
from detection.rule_engine import RuleEngine
from storage.exporter import Exporter


class TestRuleEngineDeepBranches:
    def test_rule_engine_cleartext_condition(self):
        engine = RuleEngine()
        rule = DetectionRule(
            name="Cleartext Traffic",
            match={"protocol": "TCP", "condition": "cleartext"},
            action={"alert": True},
            severity="MEDIUM",
        )

        # 1. Matching cleartext port 21 (FTP)
        pkt_match = PacketInfo(protocol="TCP", dst_port=21)
        assert engine._match_rule(pkt_match, rule) is True

        # 2. Non-cleartext port 443 (HTTPS)
        pkt_nomatch = PacketInfo(protocol="TCP", dst_port=443)
        assert engine._match_rule(pkt_nomatch, rule) is False

    def test_rule_engine_high_port_condition(self):
        engine = RuleEngine()
        rule = DetectionRule(
            name="High Port Activity",
            match={"protocol": "TCP", "condition": "high_port", "threshold": 50000},
            action={"alert": True},
            severity="LOW",
        )

        # 1. Port above threshold
        assert engine._match_rule(PacketInfo(protocol="TCP", dst_port=55000), rule) is True

        # 2. Port below threshold
        assert engine._match_rule(PacketInfo(protocol="TCP", dst_port=80), rule) is False

        # 3. None port
        assert engine._match_rule(PacketInfo(protocol="TCP", dst_port=None), rule) is False

    def test_rule_engine_mac_change_and_unknown_condition(self):
        engine = RuleEngine()

        # MAC change rule
        rule_mac = DetectionRule(
            name="MAC Changed",
            match={"protocol": "ARP", "condition": "mac_change"},
            action={"alert": True},
            severity="CRITICAL",
        )
        pkt_arp_mac = PacketInfo(protocol="ARP", old_mac="00:11:22:33:44:55", new_mac="00:11:22:33:44:aa")
        assert engine._match_rule(pkt_arp_mac, rule_mac) is True

        pkt_arp_no_mac = PacketInfo(protocol="ARP")
        assert engine._match_rule(pkt_arp_no_mac, rule_mac) is False

        # Unknown condition returns False
        rule_unknown = DetectionRule(
            name="Unknown",
            match={"protocol": "TCP", "condition": "unsupported_condition_xyz"},
            action={"alert": True},
        )
        assert engine._match_rule(PacketInfo(protocol="TCP"), rule_unknown) is False

    def test_rule_engine_reload(self):
        engine = RuleEngine()
        initial_rules = len(engine.rules)
        engine.reload()
        assert len(engine.rules) == initial_rules


class TestExporterDeepBranches:
    def test_exporter_generate_filename_and_alerts_csv(self):
        exporter = Exporter()
        fname = exporter.generate_filename("capture", "pcap")
        assert fname.startswith("capture_")
        assert fname.endswith(".pcap")

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "alerts_only.csv")
            alerts = [
                AlertInfo(id=1, timestamp_str="12:00:00", severity="HIGH", rule_name="Test Rule", message="Alert msg", src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP")
            ]
            # Alerts-only CSV export
            exporter.export_csv(csv_path, alerts=alerts)
            assert os.path.exists(csv_path)

    def test_exporter_pcap_with_scapy_layer_packets(self):
        exporter = Exporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = os.path.join(tmpdir, "scapy_raw.pcap")
            scapy_packet = IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80)
            exporter.export_pcap(pcap_path, raw_packets=[scapy_packet])
            assert os.path.exists(pcap_path)

            # Export with empty raw_packets raises ValueError
            with pytest.raises(ValueError, match="No packets provided for PCAP export"):
                exporter.export_pcap(pcap_path, raw_packets=[])
