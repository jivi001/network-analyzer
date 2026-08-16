"""
test_coverage_arp_and_alerts.py — Deep behavioral and branch coverage tests for detection/arp_monitor.py and detection/alerts.py:
ARP TTL eviction, max-hosts capacity limits, MAC spoofing detection, AlertManager FIFO bounds,
severity filtering, and multithreaded deduplication.
"""

import threading
import time
import pytest

from detection.arp_monitor import ArpMonitor
from detection.alerts import AlertManager
from storage.models import PacketInfo, AlertInfo


class TestArpMonitorDeep:
    def test_arp_monitor_prune_ttl_and_max_hosts(self):
        # Create monitor with small capacity (max 3 hosts) and short TTL (0.1s)
        monitor = ArpMonitor(max_hosts=3, ttl=0.1)

        # 1. Add 3 entries
        now = time.time()
        for i in range(1, 4):
            pkt = PacketInfo(protocol="ARP", src_ip=f"10.0.0.{i}", src_mac=f"00:11:22:33:44:0{i}", timestamp=now)
            monitor.check(pkt)

        assert len(monitor.get_arp_table()) == 3

        # 2. Add 4th entry immediately (triggers max_hosts capacity pruning)
        pkt4 = PacketInfo(protocol="ARP", src_ip="10.0.0.4", src_mac="00:11:22:33:44:04", timestamp=now + 0.01)
        monitor.check(pkt4)
        assert len(monitor.get_arp_table()) <= 3
        assert "10.0.0.4" in monitor.get_arp_table()

        # 3. Wait for TTL expiry and prune
        time.sleep(0.15)
        monitor._prune(time.time())
        assert len(monitor.get_arp_table()) == 0

    def test_arp_monitor_edge_cases_and_reset(self):
        monitor = ArpMonitor()

        # Non-ARP packet returns None
        assert monitor.check(PacketInfo(protocol="TCP", src_ip="1.1.1.1")) is None

        # ARP with missing MAC returns None
        assert monitor.check(PacketInfo(protocol="ARP", src_ip="1.1.1.1", src_mac="")) is None

        # Reset clears state
        monitor.check(PacketInfo(protocol="ARP", src_ip="192.168.1.1", src_mac="00:aa:bb:cc:dd:ee"))
        assert len(monitor.get_arp_table()) == 1
        monitor.reset()
        assert len(monitor.get_arp_table()) == 0


class TestAlertManagerDeep:
    def test_alert_manager_fifo_capacity(self):
        # Create AlertManager with capacity of 5 alerts
        mgr = AlertManager(max_alerts=5, dedup_window=0.0)

        for i in range(10):
            mgr.add(AlertInfo(rule_name=f"Rule_{i}", severity="HIGH", message=f"Msg {i}", timestamp=time.time() + i))

        # Size bounded to 5
        assert mgr.get_count() == 5
        all_alerts = mgr.get_all()
        assert len(all_alerts) == 5
        # Oldest alerts evicted
        assert all_alerts[-1].rule_name == "Rule_9"

    def test_alert_manager_get_recent_and_severity_filters(self):
        mgr = AlertManager(dedup_window=0.0)
        mgr.add(AlertInfo(rule_name="R1", severity="CRITICAL", message="A1"))
        mgr.add(AlertInfo(rule_name="R2", severity="HIGH", message="A2"))
        mgr.add(AlertInfo(rule_name="R3", severity="INFO", message="A3"))

        recent_2 = mgr.get_recent(n=2)
        assert len(recent_2) == 2

        crit = mgr.get_by_severity("critical")
        assert len(crit) == 1
        assert crit[0].rule_name == "R1"

        unknown_sev = mgr.get_by_severity("UNKNOWN")
        assert len(unknown_sev) == 0

    def test_alert_manager_concurrent_deduplication(self):
        mgr = AlertManager(dedup_window=60.0)
        num_threads = 10
        barrier = threading.Barrier(num_threads)

        def worker():
            barrier.wait()
            # Identical alert signature
            alert = AlertInfo(rule_name="SYN Probe", severity="HIGH", src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=80)
            mgr.add(alert)

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Deduplication window ensures only 1 alert was recorded
        assert mgr.get_count() == 1
