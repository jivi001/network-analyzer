"""
test_unit_core.py — Comprehensive unit tests for core modules:
stats, sniffer, processor, scanner, pcap_loader.
"""

import os
import tempfile
from unittest.mock import patch
import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR

from core.stats import StatsAggregator
from core.sniffer import PacketSniffer, CaptureState
from core.processor import process_packet
from core.scanner import NetworkScanner
from core.pcap_loader import PcapLoader
from storage.models import PacketInfo


class TestCoreStatsAggregator:
    def test_initial_state(self):
        agg = StatsAggregator()
        snap = agg.get_snapshot()
        assert snap.total_packets == 0
        assert snap.total_bytes == 0
        assert snap.unique_hosts_total == 0
        assert snap.packets_per_sec == 0.0
        assert snap.bytes_per_sec == 0.0
        assert snap.protocol_counts == {}
        assert snap.top_talkers == []

    def test_packet_recording_and_window_calculation(self):
        agg = StatsAggregator()

        pkt1 = PacketInfo(id=1, length=1000, protocol="TCP", src_ip="192.168.1.10", dst_ip="192.168.1.1")
        pkt2 = PacketInfo(id=2, length=500, protocol="UDP", src_ip="192.168.1.10", dst_ip="8.8.8.8")
        pkt3 = PacketInfo(id=3, length=200, protocol="DNS", src_ip="10.0.0.5", dst_ip="8.8.8.8")

        agg.update(pkt1)
        agg.update(pkt2)
        agg.update(pkt3)

        snap = agg.get_snapshot()
        assert snap.total_packets == 3
        assert snap.total_bytes == 1700
        assert snap.protocol_counts["TCP"] == 1
        assert snap.protocol_counts["UDP"] == 1
        assert snap.protocol_counts["DNS"] == 1
        assert snap.unique_hosts_total >= 3

        top_talkers = snap.top_talkers
        assert len(top_talkers) > 0
        assert top_talkers[0]["ip"] == "192.168.1.10"
        assert top_talkers[0]["bytes"] == 1500

    def test_top_conversations_and_hosts(self):
        agg = StatsAggregator()
        for _ in range(5):
            agg.update(PacketInfo(length=100, src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP"))
        for _ in range(2):
            agg.update(PacketInfo(length=200, src_ip="3.3.3.3", dst_ip="4.4.4.4", protocol="UDP"))

        snap = agg.get_snapshot()
        top_convs = getattr(snap, "top_conversations", []) or []
        assert len(top_convs) >= 1


class TestCorePacketProcessor:
    def test_process_ipv4_tcp_packet(self):
        scapy_pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                    IP(src="192.168.1.50", dst="192.168.1.1") / \
                    TCP(sport=54321, dport=80, flags="S") / b"GET / HTTP/1.1\r\n"
        
        info = process_packet(scapy_pkt, packet_id=1)
        assert info is not None
        assert info.src_ip == "192.168.1.50"
        assert info.dst_ip == "192.168.1.1"
        assert info.src_port == 54321
        assert info.dst_port == 80
        assert info.protocol == "TCP"

    def test_process_ipv6_udp_dns_packet(self):
        scapy_pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / \
                    UDP(sport=5353, dport=53) / \
                    DNS(rd=1, qd=DNSQR(qname="test.example.com"))
        
        info = process_packet(scapy_pkt, packet_id=2)
        assert info is not None
        assert info.src_ip == "fe80::1"
        assert info.dst_ip == "fe80::2"
        assert info.protocol in ("DNS", "UDP")
        assert info.dst_port == 53

    def test_process_arp_packet(self):
        scapy_pkt = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / \
                    ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1", hwsrc="00:11:22:33:44:55")
        
        info = process_packet(scapy_pkt, packet_id=3)
        assert info is not None
        assert info.protocol == "ARP"
        assert info.src_ip == "192.168.1.10"
        assert info.dst_ip == "192.168.1.1"

    def test_process_icmp_packet(self):
        scapy_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8)
        info = process_packet(scapy_pkt, packet_id=4)
        assert info is not None
        assert info.protocol == "ICMP"

    def test_process_malformed_or_non_packet(self):
        assert process_packet(None, packet_id=5) is None
        assert process_packet("invalid string", packet_id=6) is None


class TestCoreSniffer:
    def test_sniffer_state_and_lifecycle(self):
        sniffer = PacketSniffer(callback=lambda p: None)
        assert sniffer.state == CaptureState.IDLE

        with patch("scapy.all.sniff"):
            sniffer.start(interface="Ethernet")
            assert sniffer.state in (CaptureState.RUNNING, CaptureState.STARTING)
            sniffer.stop()
            assert sniffer.state == CaptureState.STOPPED


class TestCoreNetworkScanner:
    def test_validate_target_allowlist(self):
        scanner = NetworkScanner()
        assert scanner.validate_target("192.168.1.1") == "192.168.1.1"
        assert scanner.validate_target("10.0.0.0/24") == "10.0.0.0/24"
        assert scanner.validate_target("fe80::1") == "fe80::1"
        assert scanner.validate_target("localhost") == "localhost"
        assert scanner.validate_target("example.com") == "example.com"

        with pytest.raises(ValueError):
            scanner.validate_target("127.0.0.1; rm -rf /")
        with pytest.raises(ValueError):
            scanner.validate_target("127.0.0.1 && cat /etc/passwd")
        with pytest.raises(ValueError):
            scanner.validate_target("127.0.0.1 | whoami")

    def test_scan_profile_arguments_and_fallback(self):
        scanner = NetworkScanner()
        args = scanner._get_scan_args("stealth")
        assert "-sS" in args

        args_top = scanner._get_scan_args("top_ports")
        assert "--top-ports" in args_top


class TestCorePcapLoader:
    def test_load_synthetic_pcap(self):
        loader = PcapLoader()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            pcap_path = tf.name

        try:
            from scapy.utils import wrpcap
            pkts = [
                Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=1234, dport=80) / b"data1",
                Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=1234, dport=53) / b"data2",
            ]
            wrpcap(pcap_path, pkts)

            loaded = loader.load(pcap_path)
            assert len(loaded) == 2
            stats = loader.get_stats()
            assert stats.total_packets == 2
            assert stats.total_bytes > 0
            assert "TCP" in stats.protocol_counts
            assert "UDP" in stats.protocol_counts
        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)

    def test_load_empty_or_missing_pcap(self):
        loader = PcapLoader()
        with pytest.raises(FileNotFoundError):
            loader.load("nonexistent_pcap_file.pcap")

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            empty_path = tf.name

        try:
            with pytest.raises(ValueError):
                loader.load(empty_path)
        finally:
            if os.path.exists(empty_path):
                os.remove(empty_path)
