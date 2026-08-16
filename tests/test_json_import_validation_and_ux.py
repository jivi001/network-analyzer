import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from storage.database import Database
from storage.importer import Importer, ImportResult
from storage.exporter import Exporter
from storage.models import StatsSnapshot, AlertInfo, HostInfo, PacketInfo
from tui.menu import prompt_json_import_path
from utils.path_helpers import get_available_json_in_dir, find_similar_json, resolve_path


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    db = Database(db_path)
    yield db
    db.close()
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


@pytest.fixture
def sample_export_json_data():
    return {
        "metadata": {
            "application": "my-sentinel",
            "version": "1.0.0",
            "exported_at": "2026-08-16 10:00:00",
            "total_packets": 100,
            "total_alerts": 2,
            "total_hosts": 2,
        },
        "stats": {
            "total_packets": 100,
            "total_bytes": 15000,
            "elapsed_seconds": 10.0,
            "packets_per_sec": 10.0,
            "bytes_per_sec": 1500.0,
            "unique_hosts": 2,
            "protocol_counts": {"TCP": 80, "UDP": 20},
            "top_talkers": [{"ip": "192.168.1.10", "bytes": 10000, "packets": 70}],
        },
        "alerts": [
            {
                "timestamp": "2026-08-16 10:00:01",
                "severity": "HIGH",
                "rule_name": "SYN Probe",
                "message": "SYN Probe: 192.168.1.50 -> 192.168.1.1:80",
                "src_ip": "192.168.1.50",
                "dst_ip": "192.168.1.1",
                "dst_port": 80,
                "protocol": "TCP",
            },
            {
                "timestamp": "2026-08-16 10:00:02",
                "severity": "CRITICAL",
                "rule_name": "DNS Tunnel",
                "message": "DNS Tunnel query detected",
                "src_ip": "192.168.1.50",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "protocol": "DNS",
            },
        ],
        "hosts": [
            {
                "ip_address": "192.168.1.50",
                "mac_address": "00:11:22:33:44:55",
                "hostname": "workstation-1",
                "open_ports": [80, 443],
                "services": {"80": "http"},
                "os_guess": "Linux",
                "source": "imported",
            },
            {
                "ip_address": "192.168.1.1",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "hostname": "gateway",
                "open_ports": [53, 80],
                "services": {"53": "dns"},
                "os_guess": "RouterOS",
                "source": "imported",
            },
        ],
    }


class TestJsonImportValidationAndUX:
    """Comprehensive test suite for JSON import validation, directory selection, and error handling."""

    def test_import_valid_json_file(self, temp_db, sample_export_json_data):
        importer = Importer(temp_db)
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as tf:
            json.dump(sample_export_json_data, tf)
            json_path = tf.name

        try:
            res = importer.import_json(json_path, raise_on_error=True)
            assert res.success is True
            assert res.session_id > 0
            assert res.alert_count == 2
            assert res.host_count == 2
            assert res.packet_count == 100

            # Verify in DB
            session = temp_db.get_session(res.session_id)
            assert session is not None
            assert session.alert_count == 2
            alerts = temp_db.get_alerts(session_id=res.session_id)
            assert len(alerts) == 2
            hosts = temp_db.get_hosts()
            assert len(hosts) >= 2
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def test_import_missing_file(self, temp_db):
        importer = Importer(temp_db)
        with pytest.raises(FileNotFoundError, match="JSON file not found"):
            importer.import_json("nonexistent_path_12345.json", raise_on_error=True)

        res = importer.import_json("nonexistent_path_12345.json", raise_on_error=False)
        assert res.success is False
        assert "not found" in res.message

    def test_import_directory_rejected(self, temp_db):
        importer = Importer(temp_db)
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(IsADirectoryError, match="directory, not a file"):
                importer.import_json(tmpdir, raise_on_error=True)

            res = importer.import_json(tmpdir, raise_on_error=False)
            assert res.success is False
            assert "directory" in res.message

    def test_import_wrong_extension(self, temp_db):
        importer = Importer(temp_db)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            pcap_path = tf.name

        try:
            with pytest.raises(ValueError, match="Unsupported import file type"):
                importer.import_json(pcap_path, raise_on_error=True)
        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)

    def test_import_malformed_json(self, temp_db):
        importer = Importer(temp_db)
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as tf:
            tf.write("{malformed json: broken syntax, [}")
            bad_json_path = tf.name

        try:
            with pytest.raises(ValueError, match="Invalid JSON format"):
                importer.import_json(bad_json_path, raise_on_error=True)
        finally:
            if os.path.exists(bad_json_path):
                os.remove(bad_json_path)

    def test_import_invalid_schema(self, temp_db):
        importer = Importer(temp_db)
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as tf:
            json.dump({"unrelated_field": "some data"}, tf)
            bad_schema_path = tf.name

        try:
            with pytest.raises(ValueError, match="JSON structure is not compatible"):
                importer.import_json(bad_schema_path, raise_on_error=True)
        finally:
            if os.path.exists(bad_schema_path):
                os.remove(bad_schema_path)

    def test_export_to_import_roundtrip(self, temp_db):
        exporter = Exporter()
        importer = Importer(temp_db)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "roundtrip_export.json")

            stats = StatsSnapshot(
                total_packets=50,
                total_bytes=4000,
                elapsed_seconds=5.0,
                packets_per_sec=10.0,
                bytes_per_sec=800.0,
                unique_hosts_total=1,
            )
            alerts = [
                AlertInfo(rule_name="Test Alert", severity="HIGH", message="Roundtrip test message", timestamp_str="10:00:00")
            ]
            hosts = [
                HostInfo(ip_address="10.0.0.1", hostname="router", open_ports=[80])
            ]

            # 1. Export to JSON
            exporter.export_json(out_file, alerts=alerts, stats=stats, hosts=hosts)
            assert os.path.exists(out_file)

            # 2. Import into Database
            res = importer.import_json(out_file, raise_on_error=True)
            assert res.success is True
            assert res.alert_count == 1
            assert res.host_count == 1

            # 3. Query DB to verify
            db_alerts = temp_db.get_alerts(session_id=res.session_id)
            assert len(db_alerts) == 1
            assert db_alerts[0].rule_name == "Test Alert"

    def test_duplicate_import_handling(self, temp_db, sample_export_json_data):
        importer = Importer(temp_db)
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as tf:
            json.dump(sample_export_json_data, tf)
            json_path = tf.name

        try:
            # First import
            res1 = importer.import_json(json_path, raise_on_error=True)
            # Second import of the same file
            res2 = importer.import_json(json_path, raise_on_error=True)

            assert res1.session_id != res2.session_id
            assert res1.success is True
            assert res2.success is True
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def test_prompt_directory_input_with_selectable_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            f1 = tmp_path / "export_1.json"
            f2 = tmp_path / "export_2.json"
            f1.touch()
            f2.touch()

            # First Prompt.ask returns directory path, second Prompt.ask returns "1"
            with patch("rich.prompt.Prompt.ask", side_effect=[str(tmp_path), "1"]):
                selected = prompt_json_import_path()
                assert selected in (str(f1.resolve()), str(f2.resolve()))

    def test_prompt_quoted_path(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            valid_path = tf.name

        try:
            quoted_input = f'"{valid_path}"'
            with patch("rich.prompt.Prompt.ask", return_value=quoted_input):
                result = prompt_json_import_path()
                assert result == str(Path(valid_path).resolve())
        finally:
            if os.path.exists(valid_path):
                os.remove(valid_path)

    def test_prompt_cancel_q(self):
        with patch("rich.prompt.Prompt.ask", return_value="q"):
            result = prompt_json_import_path()
            assert result == ""
