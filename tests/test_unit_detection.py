"""
test_unit_detection.py — Comprehensive unit tests for detection engine:
AlertManager, AnomalyDetector, ArpMonitor, RuleEngine, PacketDetectionPipeline.
"""

import os
import tempfile
import time
import pytest

from detection.alerts import AlertManager
from detection.anomaly import AnomalyDetector
from detection.arp_monitor import ArpMonitor
from detection.rule_engine import RuleEngine
from detection.pipeline import PacketDetectionPipeline
from storage.models import AlertInfo, PacketInfo


class TestAlertManager:
    def test_add_and_deduplication(self):
        mgr = AlertManager()
        alert1 = AlertInfo(rule_name="SYN Probe", severity="HIGH", src_ip="192.168.1.50", dst_ip="192.168.1.1", dst_port=80, message="Probe 1")
        alert2 = AlertInfo(rule_name="SYN Probe", severity="HIGH", src_ip="192.168.1.50", dst_ip="192.168.1.1", dst_port=80, message="Probe 2")

        added1 = mgr.add(alert1)
        added2 = mgr.add(alert2)

        assert added1 is True
        # Immediate duplicate should be suppressed by deduplication window
        assert added2 is False
        assert len(mgr.get_all()) == 1

    def test_filter_by_severity(self):
        mgr = AlertManager()
        mgr.add(AlertInfo(rule_name="R1", severity="CRITICAL", message="Critical Alert", src_ip="1.1.1.1"))
        mgr.add(AlertInfo(rule_name="R2", severity="WARNING", message="Warning Alert", src_ip="1.1.1.2"))
        mgr.add(AlertInfo(rule_name="R3", severity="INFO", message="Info Alert", src_ip="1.1.1.3"))

        crits = mgr.get_by_severity("CRITICAL")
        warns = mgr.get_by_severity("WARNING")
        assert len(crits) == 1
        assert len(warns) == 1
        assert crits[0].rule_name == "R1"
        assert warns[0].rule_name == "R2"

    def test_clear_and_counts(self):
        mgr = AlertManager()
        mgr.add(AlertInfo(rule_name="R1", severity="HIGH", src_ip="2.2.2.2"))
        assert mgr.get_count() == 1
        mgr.clear()
        assert mgr.get_count() == 0


class TestAnomalyDetector:
    def test_port_scan_detection(self):
        detector = AnomalyDetector()
        alerts = []
        for port in range(1, 20):
            pkt = PacketInfo(src_ip="192.168.1.100", dst_ip="192.168.1.1", dst_port=port, protocol="TCP", flags=["SYN"], flags_raw="S", timestamp=time.time())
            alert = detector.check_port_scan(pkt)
            if alert:
                alerts.append(alert)

        assert len(alerts) >= 1
        assert "Port Scan" in alerts[0].rule_name

    def test_dns_exfiltration_detection(self):
        detector = AnomalyDetector()
        pkt = PacketInfo(
            protocol="DNS",
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            dst_port=53,
            dns_query="a89b7c6d5e4f3a2b1c0d9e8f7a6b5c4d.exfil.domain.com",
            timestamp=time.time(),
        )
        alert = detector.check_dns_exfiltration(pkt)
        assert alert is not None
        assert "DNS Exfiltration" in alert.rule_name


class TestArpMonitor:
    def test_gratuitous_arp_detection(self):
        monitor = ArpMonitor()
        pkt = PacketInfo(
            protocol="ARP",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.1",
            src_mac="00:11:22:33:44:55",
            dst_mac="ff:ff:ff:ff:ff:ff",
            timestamp=time.time(),
        )
        alert = monitor.check(pkt)
        assert alert is not None
        assert "Gratuitous ARP" in alert.rule_name

    def test_arp_poisoning_mac_change_detection(self):
        monitor = ArpMonitor()
        pkt1 = PacketInfo(protocol="ARP", src_ip="192.168.1.1", src_mac="00:11:22:33:44:aa", timestamp=time.time())
        monitor.check(pkt1)

        # Same IP claimed by different MAC
        pkt2 = PacketInfo(protocol="ARP", src_ip="192.168.1.1", src_mac="00:11:22:33:44:bb", timestamp=time.time())
        alert = monitor.check(pkt2)
        assert alert is not None
        assert "ARP Spoofing" in alert.rule_name or "ARP" in alert.rule_name


class TestRuleEngine:
    def test_rule_parsing_and_evaluation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_file = os.path.join(tmpdir, "test_syn.yaml")
            with open(rule_file, "w") as f:
                f.write("""
name: "Custom SYN Probe"
description: "Detects custom SYN probes"
severity: "HIGH"
match:
  protocol: "TCP"
  tcp_flags: "S"
  dst_port: 4444
action:
  alert: true
  message: "Probe on port 4444: {src_ip} -> {dst_ip}"
""")
            engine = RuleEngine(rules_dir=tmpdir)
            assert len(engine.rules) == 1

            matched_pkt = PacketInfo(protocol="TCP", flags=["SYN"], flags_raw="S", dst_port=4444, src_ip="1.2.3.4", dst_ip="5.6.7.8", timestamp=time.time())
            alerts = engine.evaluate(matched_pkt)
            assert len(alerts) == 1
            assert alerts[0].rule_name == "Custom SYN Probe"
            assert alerts[0].severity == "HIGH"

            unmatched_pkt = PacketInfo(protocol="TCP", flags=["SYN"], flags_raw="S", dst_port=80, src_ip="1.2.3.4", dst_ip="5.6.7.8", timestamp=time.time())
            alerts_neg = engine.evaluate(unmatched_pkt)
            assert len(alerts_neg) == 0


class TestPacketDetectionPipeline:
    def test_unified_pipeline_evaluation(self):
        engine = RuleEngine("rules")
        anomaly = AnomalyDetector()
        arp_mon = ArpMonitor()
        pipeline = PacketDetectionPipeline(engine, anomaly, arp_mon)

        pkt = PacketInfo(protocol="TCP", flags=["SYN"], flags_raw="S", dst_port=80, src_ip="10.0.0.1", dst_ip="10.0.0.2", timestamp=time.time())
        alerts = pipeline.evaluate(pkt)
        assert isinstance(alerts, list)
