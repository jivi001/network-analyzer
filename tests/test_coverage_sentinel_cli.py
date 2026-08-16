"""
test_coverage_sentinel_cli.py — Comprehensive CLI parsing, configuration validation, BPF analysis,
live capture lifecycle, and mode routing branch tests for sentinel.py.
"""

import os
import sys
import tempfile
import threading
import time
from unittest.mock import patch, MagicMock
import pytest

from sentinel import (
    get_absolute_path,
    _validate_config,
    load_config,
    validate_bpf_filter,
    run_live_capture,
    run_network_scan,
    run_pcap_analysis,
    run_history_viewer,
    run_settings,
    main,
)
from storage.database import Database
from utils.privacy import PrivacyFilter
from storage.models import ScanResult, HostInfo, PacketInfo, StatsSnapshot, SessionInfo, AlertInfo
from storage.importer import ImportResult


class TestSentinelCliAndConfig:
    def test_get_absolute_path_and_validate_config(self):
        # 1. Empty string
        assert get_absolute_path("") == ""

        # 2. Absolute path
        abs_p = os.path.abspath("sentinel_data.db")
        assert get_absolute_path(abs_p) == abs_p

        # 3. Relative path
        assert os.path.isabs(get_absolute_path("sentinel_data.db"))

        # 4. _validate_config with out of bound integers
        bad_cfg = {
            "packet_buffer_size": -5,  # Min 10
            "packet_queue_size": "invalid_int",  # Reset to default
            "refresh_fps": 100,  # Max 30
            "dedup_window": 0,  # Min 1
            "max_alerts": 5,  # Min 10
            "database_path": "",
            "export_directory": "",
            "rules_directory": "",
        }
        validated = _validate_config(bad_cfg)
        assert validated["packet_buffer_size"] == 500
        assert validated["packet_queue_size"] == 10000
        assert validated["refresh_fps"] == 10
        assert validated["dedup_window"] == 60
        assert validated["max_alerts"] == 100
        assert "sentinel_data.db" in validated["database_path"]
        assert "exports" in validated["export_directory"]
        assert "rules" in validated["rules_directory"]

    def test_load_config_with_custom_file_and_defaults(self):
        # 1. Default config load
        cfg = load_config()
        assert isinstance(cfg, dict)
        assert "database_path" in cfg

        # 2. Custom YAML config
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("capture:\n  packet_buffer_size: 750\n  refresh_fps: 15\n")
            custom_yaml = f.name

        try:
            custom_cfg = load_config(custom_yaml)
            assert custom_cfg["packet_buffer_size"] == 750
            assert custom_cfg["refresh_fps"] == 15
        finally:
            if os.path.exists(custom_yaml):
                os.remove(custom_yaml)

    def test_validate_bpf_filter_all_branches(self):
        # 1. Blank or empty filter -> valid
        assert validate_bpf_filter("") is True
        assert validate_bpf_filter("   ") is True

        # 2. Unbalanced parentheses -> invalid
        assert validate_bpf_filter("(tcp port 80 or (udp port 53)") is False

        # 3. Command injection characters -> invalid
        assert validate_bpf_filter("tcp; rm -rf /") is False
        assert validate_bpf_filter("tcp `whoami`") is False
        assert validate_bpf_filter("tcp $VAR") is False
        assert validate_bpf_filter("tcp > /dev/null") is False
        assert validate_bpf_filter("tcp | cat") is False

        # 4. Valid BPF filters
        assert validate_bpf_filter("tcp port 80 and host 192.168.1.1") is True
        assert validate_bpf_filter("ip6 and net 10.0.0.0/24") is True
        assert validate_bpf_filter("ether host 00:11:22:33:44:55") is True

        # 5. Invalid token -> invalid
        assert validate_bpf_filter("tcp port 80 invalid_token_xyz") is False


class TestSentinelLiveCaptureWorkflow:
    def test_run_live_capture_cancel_and_invalid_inputs(self):
        db = MagicMock(spec=Database)
        priv = PrivacyFilter(enabled=False)

        # 1. User cancels prompt
        with patch("sentinel.prompt_capture_settings", return_value=None):
            run_live_capture({}, db, priv)

        # 2. Invalid target IP
        with patch("sentinel.prompt_capture_settings", return_value={"interface": "eth0", "target_ip": "invalid_ip_addr", "bpf_filter": ""}):
            run_live_capture({}, db, priv)

        # 3. Invalid BPF filter syntax
        with patch("sentinel.prompt_capture_settings", return_value={"interface": "eth0", "target_ip": "", "bpf_filter": "tcp; bad_cmd"}):
            run_live_capture({}, db, priv)

    def test_run_live_capture_execution_and_flush(self):
        db = MagicMock(spec=Database)
        db.create_session.return_value = 100
        priv = PrivacyFilter(enabled=False)

        # Mock Sniffer to simulate starting and stopping
        with patch("sentinel.prompt_capture_settings", return_value={"interface": "eth0", "target_ip": "192.168.1.1", "bpf_filter": "tcp port 80"}), \
             patch("sentinel.PacketSniffer.start") as mock_sniff_start, \
             patch("sentinel.PacketSniffer.stop") as mock_sniff_stop, \
             patch("sentinel.Live.start"), \
             patch("sentinel.Live.stop"), \
             patch("sentinel.Live.update"), \
             patch("sentinel.prompt_export_settings", return_value=None), \
             patch("rich.prompt.Confirm.ask", return_value=False), \
             patch("rich.prompt.Prompt.ask", return_value=""):
            
            # Run in short thread that signals stop quickly
            t = threading.Thread(target=run_live_capture, args=({"packet_buffer_size": 100, "refresh_fps": 10}, db, priv))
            t.start()
            time.sleep(0.15)
            # Simulate KeyboardInterrupt / exiting capture
            with patch("sentinel.time.sleep", side_effect=KeyboardInterrupt):
                t.join(timeout=3.0)

            db.create_session.assert_called_once()
            db.end_session.assert_called_once()


class TestSentinelScanAndPcapWorkflows:
    def test_run_network_scan_workflow_complete(self):
        db = MagicMock(spec=Database)
        db.create_session.return_value = 1

        mock_scan_res = ScanResult(
            target="127.0.0.1",
            scan_type="discovery",
            hosts_found=1,
            hosts=[HostInfo(ip_address="127.0.0.1", state="up")],
            duration_sec=0.1,
        )

        with patch("sentinel.prompt_scan_settings", return_value={"target": "127.0.0.1", "scan_type": "discovery"}), \
             patch("sentinel.NetworkScanner.scan", return_value=mock_scan_res), \
             patch("sentinel.display_scan_progress"), \
             patch("sentinel.display_scan_results"), \
             patch("sentinel.prompt_export_settings", return_value=None), \
             patch("rich.prompt.Confirm.ask", return_value=False), \
             patch("rich.prompt.Prompt.ask", return_value=""):
            run_network_scan({}, db)

        db.save_scan_result.assert_called_once()
        db.save_host.assert_called_once()
        db.end_session.assert_called_once()

    def test_run_pcap_analysis_workflow_complete(self):
        db = MagicMock(spec=Database)
        db.create_session.return_value = 2

        pkts = [PacketInfo(id=1, length=64, protocol="TCP", src_ip="1.1.1.1", dst_ip="2.2.2.2")]

        with patch("sentinel.prompt_pcap_path", return_value="exports/test1.pcap"), \
             patch("sentinel.PcapLoader.load", return_value=pkts), \
             patch("sentinel.display_pcap_loading"), \
             patch("sentinel.display_pcap_analysis"), \
             patch("rich.prompt.Confirm.ask", return_value=True), \
             patch("sentinel.prompt_export_settings", return_value={"format": "csv", "filename": "pcap_out.csv"}), \
             patch("storage.exporter.Exporter.export_csv") as mock_exp_csv, \
             patch("rich.prompt.Prompt.ask", return_value=""):
            run_pcap_analysis({}, db, PrivacyFilter(enabled=False))

        db.create_session.assert_called_once()
        db.save_packet_summary.assert_called_once()
        mock_exp_csv.assert_called_once()


class TestSentinelHistoryAndSettings:
    def test_run_history_viewer_all_options(self):
        db = MagicMock(spec=Database)
        sample_session = SessionInfo(id=1, session_type="capture", packet_count=100)
        db.get_recent_sessions.return_value = [sample_session]
        db.get_session.return_value = sample_session
        db.get_alerts.return_value = [AlertInfo(id=1, rule_name="TestAlert", severity="HIGH")]
        db.get_hosts.return_value = [HostInfo(ip_address="10.0.0.1")]
        db.search_sessions.return_value = [sample_session]

        # 1. Choice 1: Recent Sessions with ID detail inspect
        with patch("sentinel.display_history_menu", side_effect=["1", "6"]), \
             patch("rich.prompt.Prompt.ask", side_effect=["1", ""]):
            run_history_viewer(db)

        # 2. Choice 2: Alerts with severity filter
        with patch("sentinel.display_history_menu", side_effect=["2", "6"]), \
             patch("rich.prompt.Prompt.ask", side_effect=["HIGH", ""]):
            run_history_viewer(db)

        # 3. Choice 3: Hosts
        with patch("sentinel.display_history_menu", side_effect=["3", "6"]), \
             patch("rich.prompt.Prompt.ask", return_value=""):
            run_history_viewer(db)

        # 4. Choice 4: Search
        with patch("sentinel.display_history_menu", side_effect=["4", "6"]), \
             patch("rich.prompt.Prompt.ask", side_effect=["test_query", ""]):
            run_history_viewer(db)

        # 5. Choice 5: JSON Import
        mock_import_res = ImportResult(success=True, session_id=5, total_records=10, alert_count=1, host_count=1, packet_count=8, total_bytes=1024)
        with patch("sentinel.display_history_menu", side_effect=["5", "6"]), \
             patch("tui.menu.prompt_json_import_path", return_value="exports/session.json"), \
             patch("storage.importer.Importer.import_json", return_value=mock_import_res), \
             patch("rich.prompt.Prompt.ask", return_value=""):
            run_history_viewer(db)

    def test_run_settings_menu_toggle(self):
        cfg = {"privacy_mask": False, "packet_buffer_size": 500, "refresh_fps": 10}
        priv = PrivacyFilter(enabled=False)

        with patch("rich.prompt.Confirm.ask", return_value=True), \
             patch("rich.prompt.Prompt.ask", return_value=""):
            run_settings(cfg, priv)
            assert priv.enabled is True


class TestSentinelMainEntrypoint:
    def test_main_cli_flags_capture_scan_pcap(self):
        # 1. Direct Capture mode
        with patch("sys.argv", ["sentinel", "--capture", "--no-admin-check"]), \
             patch("sentinel.run_live_capture") as mock_cap:
            main()
            mock_cap.assert_called_once()

        # 2. Direct Scan mode
        with patch("sys.argv", ["sentinel", "--scan", "192.168.1.1", "--profile", "service", "--no-admin-check"]), \
             patch("sentinel.check_nmap_installed", return_value=True), \
             patch("sentinel.NetworkScanner.scan", return_value=ScanResult(target="192.168.1.1", hosts=[])), \
             patch("sentinel.display_scan_progress"), \
             patch("sentinel.display_scan_results"):
            main()

        # 3. Direct PCAP mode
        with patch("sys.argv", ["sentinel", "--pcap", "exports/test.pcap", "--no-admin-check"]), \
             patch("sentinel.run_pcap_analysis") as mock_pcap:
            main()
            mock_pcap.assert_called_once()

    def test_main_interactive_menu_loop_and_exit(self):
        with patch("sys.argv", ["sentinel", "--no-admin-check"]), \
             patch("sentinel.show_main_menu", side_effect=["6"]):
            main()

    def test_main_keyboard_interrupt_graceful_exit(self):
        with patch("sys.argv", ["sentinel", "--no-admin-check"]), \
             patch("sentinel.show_main_menu", side_effect=KeyboardInterrupt):
            main()
