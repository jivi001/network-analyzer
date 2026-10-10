"""
Regression and verification test suite for Phase 1 export correctness.
Verifies CSV, JSON, and PCAP export contracts, argument safety, and data integrity.
"""

import os
import csv
import json
import tempfile
import pytest
from typing import List

from scapy.all import Ether, IP, TCP, rdpcap

from storage.exporter import Exporter
from storage.importer import Importer
from storage.database import Database
from storage.models import PacketInfo, AlertInfo, StatsSnapshot, HostInfo


class TestExportCorrectnessPhase1:
    """Tests covering Scope B export pipeline correctness and regression prevention."""

    @pytest.fixture
    def exporter(self):
        return Exporter(allow_absolute=True)

    @pytest.fixture
    def sample_packets(self) -> List[PacketInfo]:
        return [
            PacketInfo(
                id=1,
                timestamp=1700000000.123,
                timestamp_str="12:34:56.123",
                src_ip="192.168.1.50",
                src_port=54321,
                dst_ip="10.0.0.1",
                dst_port=443,
                protocol="TCP",
                length=1500,
                service="HTTPS",
                info="TLS Client Hello",
            ),
            PacketInfo(
                id=2,
                timestamp=1700000001.456,
                timestamp_str="12:34:57.456",
                src_ip="10.0.0.1",
                src_port=443,
                dst_ip="192.168.1.50",
                dst_port=54321,
                protocol="TCP",
                length=200,
                service="HTTPS",
                info="TLS Server Hello",
            ),
        ]

    @pytest.fixture
    def sample_alerts(self) -> List[AlertInfo]:
        return [
            AlertInfo(
                id=1,
                timestamp=1700000000.123,
                timestamp_str="12:34:56.123",
                severity="HIGH",
                rule_name="SynScanRule",
                message="SYN scan detected from host",
                src_ip="192.168.1.50",
                dst_ip="10.0.0.1",
                dst_port=443,
                protocol="TCP",
            )
        ]

    @pytest.fixture
    def sample_stats(self) -> StatsSnapshot:
        return StatsSnapshot(
            total_packets=2,
            total_bytes=1700,
            elapsed_seconds=1.333,
            packets_per_sec=1.5,
            bytes_per_sec=1275.3,
            unique_hosts_total=2,
            protocol_counts={"TCP": 2},
            top_talkers=[("192.168.1.50", 1500), ("10.0.0.1", 200)],
        )

    def test_export_csv_packets_with_keyword_contract(self, exporter, sample_packets, sample_stats):
        """Verify export_csv with explicit keyword arguments outputs correct packet records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "packets.csv")
            exporter.export_csv(out_file, packets=sample_packets, stats=sample_stats)

            assert os.path.exists(out_file)
            with open(out_file, "r", newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))

            assert len(rows) == 3  # 1 header + 2 packets
            assert rows[0] == [
                "id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
                "protocol", "length", "service", "info"
            ]
            assert rows[1][0] == "1"
            assert rows[1][2] == "192.168.1.50"
            assert rows[1][3] == "54321"
            assert rows[1][4] == "10.0.0.1"
            assert rows[1][5] == "443"
            assert rows[1][6] == "TCP"
            assert rows[1][7] == "1500"
            assert rows[1][8] == "HTTPS"
            assert rows[1][9] == "TLS Client Hello"

    def test_export_csv_positional_stats_snapshot_type_enforcement(self, exporter, sample_stats):
        """
        Regression Test: Passing StatsSnapshot positionally into the alerts parameter
        is not supported and raises TypeError, enforcing the keyword contract.
        Passing via explicit stats= keyword argument succeeds.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "positional_empty.csv")
            # Positional mis-binding raises TypeError when alerts is iterated
            with pytest.raises(TypeError):
                exporter.export_csv(out_file, [], sample_stats)

            # Keyword call succeeds and writes valid empty packet headers
            valid_file = os.path.join(tmpdir, "keyword_valid.csv")
            exporter.export_csv(valid_file, packets=[], stats=sample_stats)
            assert os.path.exists(valid_file)
            with open(valid_file, "r", newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))
            assert len(rows) == 1  # Only header
            assert rows[0][0] == "id"
            assert rows[0][2] == "src_ip"

    def test_export_csv_alerts_only_contract(self, exporter, sample_alerts):
        """Verify export_csv writes the alert schema when alerts are provided without packets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "alerts.csv")
            exporter.export_csv(out_file, alerts=sample_alerts)

            assert os.path.exists(out_file)
            with open(out_file, "r", newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))

            assert len(rows) == 2  # 1 header + 1 alert
            assert rows[0] == [
                "id", "timestamp", "severity", "rule_name", "message",
                "src_ip", "dst_ip", "dst_port", "protocol"
            ]
            assert rows[1][0] == "1"
            assert rows[1][2] == "HIGH"
            assert rows[1][3] == "SynScanRule"
            assert rows[1][4] == "SYN scan detected from host"
            assert rows[1][5] == "192.168.1.50"
            assert rows[1][6] == "10.0.0.1"
            assert rows[1][7] == "443"
            assert rows[1][8] == "TCP"

    def test_export_csv_empty_dataset(self, exporter):
        """Verify empty datasets produce standard packet headers without raising exceptions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "empty.csv")
            exporter.export_csv(out_file, packets=[], alerts=[])

            assert os.path.exists(out_file)
            with open(out_file, "r", newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))
            assert len(rows) == 1
            assert rows[0][0] == "id"
            assert rows[0][1] == "timestamp"

    def test_export_csv_special_characters_escaping(self, exporter):
        """Verify fields containing commas, double quotes, newlines, and Unicode round-trip cleanly."""
        special_packet = PacketInfo(
            id=10,
            timestamp_str="12:00:00",
            src_ip="10.0.0.1",
            src_port=80,
            dst_ip="10.0.0.2",
            dst_port=8080,
            protocol="HTTP",
            length=256,
            service="HTTP,Custom",
            info='POST /api/v1 HTTP/1.1\r\nHost: "example.org"\nData: val1,val2\nStatus: ⚠️ Alert 日本語',
        )
        special_alert = AlertInfo(
            id=20,
            timestamp_str="12:00:00",
            severity="CRITICAL",
            rule_name='Rule "Injection, SQL"',
            message="Payload: ' OR '1'='1 --\nLine 2, with comma\nUnicode: 🛡️",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            dst_port=8080,
            protocol="HTTP",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Packet CSV with special chars
            p_out = os.path.join(tmpdir, "special_pkts.csv")
            exporter.export_csv(p_out, packets=[special_packet])
            with open(p_out, "r", newline="", encoding="utf-8") as f:
                p_rows = list(csv.reader(f))
            assert len(p_rows) == 2
            assert p_rows[1][8] == "HTTP,Custom"
            assert p_rows[1][9] == special_packet.info

            # 2. Alert CSV with special chars
            a_out = os.path.join(tmpdir, "special_alerts.csv")
            exporter.export_csv(a_out, alerts=[special_alert])
            with open(a_out, "r", newline="", encoding="utf-8") as f:
                a_rows = list(csv.reader(f))
            assert len(a_rows) == 2
            assert a_rows[1][3] == 'Rule "Injection, SQL"'
            assert a_rows[1][4] == special_alert.message

    def test_export_csv_invalid_destinations_and_traversal(self, exporter, sample_packets):
        """Verify invalid export filenames and path traversal are rejected with ValueError."""
        with pytest.raises(ValueError, match="Path traversal detected"):
            exporter.export_csv("../escaped.csv", packets=sample_packets)

        with pytest.raises(ValueError, match="Unsupported export format"):
            exporter.export_csv("invalid_ext.txt", packets=sample_packets)

        with pytest.raises(ValueError, match="Invalid export filename"):
            exporter.export_csv("", packets=sample_packets)

    def test_export_json_keyword_contract_and_structure(self, exporter, sample_packets, sample_alerts, sample_stats):
        """Verify export_json writes complete metadata, stats, alerts, and packets sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "export.json")
            exporter.export_json(
                out_file,
                alerts=sample_alerts,
                stats=sample_stats,
                packets=sample_packets,
            )

            assert os.path.exists(out_file)
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            assert "metadata" in data
            assert data["metadata"]["application"] == "my-sentinel"
            assert data["metadata"]["total_packets"] == 2
            assert data["metadata"]["total_alerts"] == 1

            assert "stats" in data
            assert data["stats"]["total_packets"] == 2
            assert data["stats"]["total_bytes"] == 1700
            assert data["stats"]["protocol_counts"] == {"TCP": 2}

            assert "alerts" in data
            assert len(data["alerts"]) == 1
            assert data["alerts"][0]["rule_name"] == "SynScanRule"

            assert "packets" in data
            assert len(data["packets"]) == 2
            assert data["packets"][0]["info"] == "TLS Client Hello"

    def test_export_pcap_validation_failures(self, exporter):
        """Verify export_pcap raises ValueError on empty or missing raw packet layer data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_pcap = os.path.join(tmpdir, "empty.pcap")

            # 1. Empty packet list
            with pytest.raises(ValueError, match="No packets provided for PCAP export"):
                exporter.export_pcap(out_pcap, raw_packets=[])

            # 2. PacketInfo without raw_packet
            packet_no_raw = PacketInfo(id=1, raw_packet=None)
            with pytest.raises(ValueError, match="No raw packet layer data available for PCAP export"):
                exporter.export_pcap(out_pcap, raw_packets=[packet_no_raw])

    def test_export_pcap_roundtrip_readback(self, exporter):
        """Verify valid PCAP export with raw packet data and successful binary read-back."""
        raw_pkt1 = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1234, dport=80)
        raw_pkt2 = Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=1234)

        pkt_info1 = PacketInfo(id=1, raw_packet=raw_pkt1)
        pkt_info2 = PacketInfo(id=2, raw_packet=raw_pkt2)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_pcap = os.path.join(tmpdir, "valid_capture.pcap")
            exporter.export_pcap(out_pcap, raw_packets=[pkt_info1, pkt_info2])

            assert os.path.exists(out_pcap)
            assert os.path.getsize(out_pcap) > 0

            # Binary read-back validation via Scapy rdpcap
            read_packets = rdpcap(out_pcap)
            assert len(read_packets) == 2
            assert read_packets[0].haslayer(IP)
            assert read_packets[0][IP].src == "192.168.1.10"
            assert read_packets[0][IP].dst == "192.168.1.20"
            assert read_packets[1][IP].src == "192.168.1.20"
            assert read_packets[1][IP].dst == "192.168.1.10"

    def test_export_csv_with_stats_snapshot(self, exporter, sample_packets, sample_stats):
        """Verify export_csv accepts stats keyword argument without corrupting alerts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "packets_stats.csv")
            exporter.export_csv(out_file, packets=sample_packets, stats=sample_stats)

            assert os.path.exists(out_file)
            with open(out_file, "r", newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))
            assert len(rows) == 3
            assert rows[0][0] == "id"
            assert rows[1][2] == "192.168.1.50"

    def test_export_json_without_stats_schema_valid_and_importable(self, exporter, sample_alerts):
        """Verify export_json without stats produces valid schema and imports into database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "alerts_no_stats.json")
            db_path = os.path.join(tmpdir, "test.db")
            db = Database(db_path)
            importer = Importer(db)

            exporter.export_json(out_file, alerts=sample_alerts)
            assert os.path.exists(out_file)

            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            valid, msg = importer.validate_json_schema(data)
            assert valid is True, f"JSON without stats must pass schema validation: {msg}"
            assert isinstance(data.get("stats"), dict)

            result = importer.import_json(out_file)
            assert result.success is True
            assert result.alert_count == len(sample_alerts)

    def test_export_json_unicode_and_special_characters(self, exporter):
        """Verify export_json handles Unicode and special characters without encoding errors."""
        special_packet = PacketInfo(
            id=1,
            timestamp_str="12:00:00",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="HTTP",
            info="Special: ⚠️ Alert 日本語 / <script>alert(1)</script> \r\n \"quotes\"",
        )
        special_alert = AlertInfo(
            id=1,
            timestamp_str="12:00:00",
            severity="HIGH",
            rule_name="UnicodeRule 🛡️",
            message="Injection test: ' OR 1=1 -- \n\t\"quoted\"",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="TCP",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "special.json")
            exporter.export_json(out_file, alerts=[special_alert], packets=[special_packet])
            assert os.path.exists(out_file)

            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            assert data["alerts"][0]["rule_name"] == "UnicodeRule 🛡️"
            assert data["alerts"][0]["message"] == special_alert.message
            assert data["packets"][0]["info"] == special_packet.info

    def test_export_pcap_direct_scapy_packets(self, exporter):
        """Verify export_pcap accepts bare Scapy packets directly (not wrapped in PacketInfo)."""
        raw1 = Ether() / IP(src="10.1.1.1", dst="10.2.2.2") / TCP(sport=5555, dport=80)
        raw2 = Ether() / IP(src="10.2.2.2", dst="10.1.1.1") / TCP(sport=80, dport=5555)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_pcap = os.path.join(tmpdir, "bare_packets.pcap")
            exporter.export_pcap(out_pcap, raw_packets=[raw1, raw2])

            assert os.path.exists(out_pcap)
            assert os.path.getsize(out_pcap) > 0

            read = rdpcap(out_pcap)
            assert len(read) == 2
            assert read[0][IP].src == "10.1.1.1"
            assert read[1][IP].src == "10.2.2.2"
