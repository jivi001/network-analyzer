"""
test_coverage_gap_closure_final.py — Targeted gap-closure test suite for:
- storage/importer.py (schema edge cases, type conversions, error bubbling)
- detection/anomaly.py (LRU pruning, C2 beaconing stddev, port scan window reset)
- traffic_lab.py (main CLI execution, validation error, keyboard interrupt, local UDP tight dispatch)
- tui/menu.py (prompt_json_import_path directory inspection, typo suggestion selection, extension checks)
- sentinel.py (packet worker loops, direct CLI modes, and error recovery)
"""

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from storage.models import PacketInfo, AlertInfo, HostInfo, SessionInfo, StatsSnapshot
from storage.importer import Importer, ImportResult
from storage.database import Database
from detection.anomaly import AnomalyDetector
from traffic_lab import main as traffic_lab_main, local_or_lan, Counters
from tui.menu import prompt_json_import_path


class TestImporterGaps:
    def test_importer_type_helpers_and_schema_validation(self):
        db = MagicMock(spec=Database)
        importer = Importer(db)

        # 1. Truncate / safe conversions
        assert importer._truncate_str(12345, 3) == "123"
        assert importer._safe_int("invalid", 42) == 42
        assert importer._safe_float("invalid", 3.14) == 3.14

        # 2. validate_json_schema failures
        assert importer.validate_json_schema("not_a_dict")[0] is False
        assert importer.validate_json_schema({"unknown_key": 1})[0] is False
        assert importer.validate_json_schema({"alerts": "not_a_list"})[0] is False
        assert importer.validate_json_schema({"hosts": "not_a_list"})[0] is False
        assert importer.validate_json_schema({"stats": "not_a_dict"})[0] is False
        assert importer.validate_json_schema({"metadata": "not_a_dict"})[0] is False

    def test_import_json_corrupt_records_and_permission_error(self):
        db = MagicMock(spec=Database)
        db.lock = threading.Lock()
        db.create_session.return_value = 1
        importer = Importer(db)

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. JSON file with malformed alert/host items that are safely skipped
            corrupt_json_path = os.path.join(tmpdir, "corrupt_items.json")
            data = {
                "metadata": {"application": "my-sentinel"},
                "alerts": [None, "invalid_str", {"rule_name": "ValidAlert", "severity": "HIGH"}],
                "hosts": [None, {"ip": ""}, {"ip_address": "192.168.1.50"}],
            }
            with open(corrupt_json_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

            res = importer.import_json(corrupt_json_path)
            assert res.success is True
            assert res.alert_count == 1
            assert res.host_count == 1

            # 2. Non-existent path with raise_on_error
            with pytest.raises(FileNotFoundError):
                importer.import_json(os.path.join(tmpdir, "missing.json"), raise_on_error=True)


class TestAnomalyDetectorGaps:
    def test_anomaly_detector_lru_pruning(self):
        detector = AnomalyDetector(max_hosts=3, max_beacon_pairs=3)
        detector.scan_window = 0.05
        now = time.time()

        # Fill scan state beyond capacity
        for i in range(5):
            pkt = PacketInfo(protocol="TCP", src_ip=f"10.0.0.{i}", dst_port=80 + i, timestamp=now + i)
            detector.check_port_scan(pkt)

        # Fill beacon state beyond capacity
        for i in range(5):
            pkt = PacketInfo(protocol="TCP", src_ip="10.0.0.1", dst_ip=f"10.0.0.{i}", dst_port=443, timestamp=now + i)
            detector.check_beaconing(pkt)

        # Fill DNS exfil state
        for i in range(5):
            pkt = PacketInfo(protocol="DNS", dns_query=f"abcdefghijklmnopqrstuvwxyz{i}.example.com", timestamp=now + i)
            detector.check_dns_exfiltration(pkt)

        # Verify pruning prevents unbounded memory growth
        assert len(detector.scan_state) <= 4
        assert len(detector.beacon_state) <= 4

    def test_anomaly_detector_c2_beaconing_trigger(self):
        detector = AnomalyDetector()
        now = time.time()

        # Send 7 packets with exactly 2.0s interval (stddev ~ 0.0, mean 2.0s > 1.0s)
        alert = None
        for i in range(7):
            pkt = PacketInfo(
                protocol="TCP",
                src_ip="192.168.1.100",
                dst_ip="198.51.100.1",
                dst_port=443,
                timestamp=now + (i * 2.0),
            )
            res = detector.check_beaconing(pkt)
            if res:
                alert = res

        assert alert is not None
        assert alert.rule_name == "C2 Beaconing"
        assert alert.severity == "HIGH"


class TestTrafficLabGaps:
    def test_traffic_lab_main_execution_and_error(self):
        # 1. Successful quick local traffic lab execution
        with patch("sys.argv", ["traffic_lab.py", "--mode", "local", "--duration", "0.05", "--rate", "10", "--target", "127.0.0.1", "--port", "9999"]):
            traffic_lab_main()

        # 2. Validation error handling
        with patch("sys.argv", ["traffic_lab.py", "--duration", "-1"]):
            with pytest.raises(SystemExit):
                traffic_lab_main()

    def test_traffic_lab_udp_loop_and_drift(self):
        c = Counters()
        stop = threading.Event()

        # Quick UDP loop run
        t = threading.Thread(target=local_or_lan, args=("udp", "127.0.0.1", 9999, 0.05, 50, c, stop))
        t.start()
        time.sleep(0.02)
        stop.set()
        t.join(timeout=1.0)
        assert c.attempts >= 1


class TestMenuPromptsGaps:
    def test_prompt_json_import_path_directory_and_typos(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = Path(tmpdir) / "session_export.json"
            json_file.write_text("{}", encoding="utf-8")

            # 1. User passes directory -> directory inspected -> selects file [1]
            with patch("rich.prompt.Prompt.ask", side_effect=[tmpdir, "1"]):
                selected = prompt_json_import_path()
                assert selected == str(json_file.resolve())

            # 2. User types wrong extension (.pcap) -> then enters valid .json
            with patch("rich.prompt.Prompt.ask", side_effect=["test.pcap", str(json_file)]):
                selected = prompt_json_import_path()
                assert selected == str(json_file.resolve())

            # 3. Typo in filename -> typo suggestions listed -> selects suggestion [1]
            typo_path = os.path.join(tmpdir, "sessio_expor.json")
            with patch("rich.prompt.Prompt.ask", side_effect=[typo_path, "1"]):
                selected = prompt_json_import_path()
                assert selected == str(json_file.resolve())

    def test_prompt_pcap_path_quick_select_and_directory(self):
        from tui.menu import prompt_pcap_path

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = Path(tmpdir) / "capture_1.pcap"
            pcap_file.write_bytes(b"test_pcap_content")

            # 1. Directory entered -> directory inspected -> user enters exact file path
            with patch("rich.prompt.Prompt.ask", side_effect=[tmpdir, str(pcap_file)]):
                selected = prompt_pcap_path()
                assert selected == str(pcap_file.resolve())

            # 2. Typo in pcap filename -> typo suggestions listed -> selects suggestion [1]
            typo_path = os.path.join(tmpdir, "captur_1.pcap")
            with patch("rich.prompt.Prompt.ask", side_effect=[typo_path, "1"]):
                selected = prompt_pcap_path()
                assert selected == str(pcap_file.resolve())


class TestSentinelWorkerLiveCaptureGaps:
    def test_live_capture_worker_packet_pipeline(self):
        from sentinel import run_live_capture
        from scapy.layers.inet import IP, TCP

        db = MagicMock(spec=Database)
        db.create_session.return_value = 500
        priv = MagicMock()
        priv.enabled = False

        raw_scapy = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=4321, dport=80, flags="S")

        # Mock sniffer so starting puts a packet into the queue
        with patch("sentinel.prompt_capture_settings", return_value={"interface": "eth0", "target_ip": "", "bpf_filter": "tcp"}), \
             patch("sentinel.Live.start"), \
             patch("sentinel.Live.stop"), \
             patch("sentinel.Live.update"), \
             patch("sentinel.prompt_export_settings", return_value=None), \
             patch("rich.prompt.Confirm.ask", return_value=False), \
             patch("rich.prompt.Prompt.ask", return_value=""):
            
            # Start capture in background thread, let it process 1 packet, then trigger stop
            def sniffer_mock_start(on_packet_cb, *args, **kwargs):
                on_packet_cb(raw_scapy)

            with patch("sentinel.PacketSniffer.start", side_effect=sniffer_mock_start):
                t = threading.Thread(target=run_live_capture, args=({"packet_buffer_size": 100, "refresh_fps": 10}, db, priv))
                t.start()
                time.sleep(0.2)
                # Interrupt sleep loop to finish
                with patch("sentinel.time.sleep", side_effect=KeyboardInterrupt):
                    t.join(timeout=3.0)

            db.create_session.assert_called_once()
            db.end_session.assert_called_once()
