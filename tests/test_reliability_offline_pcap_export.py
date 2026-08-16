import csv
import json
import os
import tempfile
import time
from unittest.mock import patch, MagicMock
import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, ARP, ICMP, wrpcap, rdpcap

from core.processor import process_packet
from core.pcap_loader import PcapLoader
from core.stats import StatsAggregator, _sample_process_memory_mb
from storage.exporter import Exporter
from storage.models import PacketInfo, AlertInfo, HostInfo, StatsSnapshot
import traffic_lab


class TestTrafficLabReliability:
    """Test suite for traffic generator rate control and diagnostic accounting."""

    def test_counters_accounting_on_failure(self):
        c = traffic_lab.Counters()
        assert c.attempts == 0
        assert c.successes == 0
        assert c.failures == 0

        # Simulate failed connection attempt (e.g. timeout on closed port)
        c.attempt(tx=32)
        c.failure("timeout")

        assert c.attempts == 1
        assert c.successes == 0
        assert c.failures == 1
        assert c.timeouts == 1
        assert c.tx == 32

    def test_counters_accounting_on_refused(self):
        c = traffic_lab.Counters()
        c.attempt(tx=64)
        c.failure("refused")

        assert c.attempts == 1
        assert c.failures == 1
        assert c.refused == 1

    def test_validate_args(self):
        # Valid internet mode
        args = MagicMock(mode="internet", duration=60, rate=30, target="127.0.0.1", port=80)
        traffic_lab.validate(args)

        # Invalid duration
        args.duration = 0
        with pytest.raises(ValueError, match="duration"):
            traffic_lab.validate(args)
        args.duration = 60

        # Invalid rate
        args.rate = -5
        with pytest.raises(ValueError, match="rate"):
            traffic_lab.validate(args)
        args.rate = 30

        # Internet mode cap exceeded
        args.rate = 100
        with pytest.raises(ValueError, match="internet mode is capped"):
            traffic_lab.validate(args)
        args.rate = 30

        # High rate on non-private target
        args.mode = "tcp"
        args.target = "8.8.8.8"
        with pytest.raises(ValueError, match="high-rate TCP/UDP targets must be private"):
            traffic_lab.validate(args)


class TestOfflinePcapForensics:
    """Test suite for offline PCAP loading, parsing, duration, and error handling."""

    @pytest.fixture
    def sample_pcap_file(self):
        """Creates a temporary PCAP file containing diverse packets spanning 10 seconds."""
        t0 = 1700000000.0
        packets = [
            # 1. ARP Request at t0
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1", hwsrc="00:11:22:33:44:55"),
            # 2. IPv4 TCP SYN at t0 + 2.0s
            Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="S"),
            # 3. IPv4 UDP DNS Query at t0 + 5.0s
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(qd=DNSQR(qname="test.example.com")),
            # 4. IPv6 UDP Packet at t0 + 8.0s
            Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=9000, dport=9001),
            # 5. IPv4 ICMP Echo at t0 + 10.0s
            Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / ICMP(type=8, code=0),
        ]

        timestamps = [t0, t0 + 2.0, t0 + 5.0, t0 + 8.0, t0 + 10.0]
        for pkt, ts in zip(packets, timestamps):
            pkt.time = ts

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            pcap_path = tf.name

        wrpcap(pcap_path, packets)
        yield pcap_path

        if os.path.exists(pcap_path):
            os.remove(pcap_path)

    def test_pcap_loader_forensic_metrics_and_duration(self, sample_pcap_file):
        loader = PcapLoader()
        pkts = loader.load(sample_pcap_file)

        assert len(pkts) == 5
        assert loader.get_packet_count() == 5

        # Check IPv4, IPv6, ARP, DNS, ICMP decoded correctly
        protocols = [p.protocol for p in pkts]
        assert "ARP" in protocols
        assert "TCP" in protocols
        assert "DNS" in protocols
        assert "UDP" in protocols
        assert "ICMP" in protocols

        # Check forensic duration calculation
        stats = loader.get_stats()
        assert pytest.approx(stats.elapsed_seconds, 0.1) == 10.0
        assert pytest.approx(stats.packets_per_sec, 0.1) == 0.5  # 5 pkts / 10s
        assert stats.total_packets == 5
        assert stats.total_bytes > 0
        assert len(stats.top_talkers) > 0

    def test_pcap_loader_empty_file_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            empty_path = tf.name

        try:
            loader = PcapLoader()
            with pytest.raises(ValueError, match="empty"):
                loader.load(empty_path)
        finally:
            if os.path.exists(empty_path):
                os.remove(empty_path)

    def test_pcap_loader_nonexistent_file_rejected(self):
        loader = PcapLoader()
        with pytest.raises(FileNotFoundError, match="not found"):
            loader.load("non_existent_file_12345.pcap")

    def test_pcap_loader_corrupt_file_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            corrupt_path = tf.name
            tf.write(b"NOT A PCAP FILE JUST RANDOM GARBAGE DATA 1234567890")

        try:
            loader = PcapLoader()
            with pytest.raises(ValueError, match="Corrupt or invalid PCAP format"):
                loader.load(corrupt_path)
        finally:
            # Short sleep to allow Scapy reader fd to close on Windows
            time.sleep(0.05)
            if os.path.exists(corrupt_path):
                try:
                    os.remove(corrupt_path)
                except OSError:
                    pass


class TestFormatSpecificExporter:
    """Test suite for valid format-specific PCAP, CSV, and JSON exports."""

    @pytest.fixture
    def sample_data(self):
        p1 = process_packet(
            Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=50000, dport=443, flags="S"),
            packet_id=1,
        )
        p2 = process_packet(
            Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=50001, dport=53) / DNS(qd=DNSQR(qname="example.org")),
            packet_id=2,
        )
        alerts = [
            AlertInfo(
                id=1,
                timestamp_str="12:00:01.100",
                severity="CRITICAL",
                rule_name="DNS Exfiltration",
                message="DNS query entropy anomaly",
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="DNS",
            )
        ]
        hosts = [
            HostInfo(
                id=1,
                ip_address="192.168.1.100",
                mac_address="00:11:22:33:44:55",
                hostname="desktop-lab",
                open_ports=[443],
                services={"443/tcp": {"name": "https"}},
                state="up",
            )
        ]
        stats = StatsSnapshot(
            total_packets=2,
            total_bytes=150,
            elapsed_seconds=1.5,
            packets_per_sec=1.33,
            bytes_per_sec=100.0,
            unique_hosts_total=2,
            protocol_counts={"TCP": 1, "DNS": 1},
        )
        return [p1, p2], alerts, hosts, stats

    def test_export_pcap_binary_validity(self, sample_data):
        packets, _, _, _ = sample_data
        exporter = Exporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            out_pcap = os.path.join(tmpdir, "test_out.pcap")
            exporter.export_pcap(out_pcap, packets)

            assert os.path.exists(out_pcap)
            assert os.path.getsize(out_pcap) > 0

            # Verify with Scapy rdpcap
            reopened = rdpcap(out_pcap)
            assert len(reopened) == 2
            assert reopened[0].haslayer(IP)
            assert reopened[0][IP].src == "192.168.1.100"

    def test_export_csv_validity(self, sample_data):
        packets, alerts, _, stats = sample_data
        exporter = Exporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            out_csv = os.path.join(tmpdir, "test_out.csv")
            exporter.export_csv(out_csv, packets=packets, stats=stats)

            assert os.path.exists(out_csv)
            with open(out_csv, "r", encoding="utf-8") as f:
                reader = list(csv.reader(f))
                assert len(reader) == 3  # Header + 2 rows
                assert reader[0][0] == "id"
                assert reader[0][2] == "src_ip"
                assert reader[1][2] == "192.168.1.100"
                assert reader[2][6] == "DNS"

    def test_export_json_validity(self, sample_data):
        packets, alerts, hosts, stats = sample_data
        exporter = Exporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = os.path.join(tmpdir, "test_out.json")
            exporter.export_json(out_json, alerts=alerts, stats=stats, hosts=hosts, packets=packets)

            assert os.path.exists(out_json)
            with open(out_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                assert "metadata" in data
                assert data["metadata"]["application"] == "my-sentinel"
                assert "stats" in data
                assert data["stats"]["total_packets"] == 2
                assert len(data["alerts"]) == 1
                assert data["alerts"][0]["rule_name"] == "DNS Exfiltration"
                assert len(data["hosts"]) == 1
                assert len(data["packets"]) == 2

    def test_export_path_traversal_and_format_validation(self):
        exporter = Exporter()
        with pytest.raises(ValueError, match="Path traversal"):
            exporter.validate_export_path("../../../evil.json")

        with pytest.raises(ValueError, match="Unsupported export format"):
            exporter.validate_export_path("malicious.exe")


class TestSystemTelemetryAndBacklog:
    """Test suite for sampled system telemetry and backlog detection."""

    def test_stats_aggregator_telemetry_sampling(self):
        agg = StatsAggregator()
        pkt = process_packet(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=53), 1)
        agg.update(pkt)

        # Trigger one calc loop step
        agg._calc_loop_step = True
        snapshot = agg.get_snapshot()

        assert snapshot.total_packets == 1
        assert snapshot.thread_count >= 1
        assert isinstance(snapshot.cpu_percent, float)
        assert isinstance(snapshot.memory_mb, float)
        assert len(snapshot.top_conversations) == 1
        assert snapshot.top_conversations[0]["src"] == "10.0.0.1"
        assert snapshot.top_conversations[0]["dst"] == "10.0.0.2"

    def test_memory_sampler_function(self):
        mem = _sample_process_memory_mb()
        assert isinstance(mem, float)
        assert mem >= 0.0
