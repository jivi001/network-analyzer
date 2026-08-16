"""
test_coverage_utils_deep.py — Deep branch coverage tests for utils/privacy.py, utils/console.py,
utils/path_helpers.py, and detection/alerts.py.
"""

import os
import signal
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from utils.privacy import mask_ip, mask_mac, mask_text, PrivacyFilter
from utils.console import (
    enter_alt_screen,
    exit_alt_screen,
    clear_screen,
    _signal_handler,
    ScreenManager,
    ScreenState,
)
from utils.path_helpers import (
    clean_path_input,
    resolve_path,
    get_available_files_in_dir,
    find_similar_pcap,
    find_similar_json,
)
from detection.alerts import AlertManager
from storage.models import AlertInfo


class TestUtilsPrivacyDeep:
    def test_mask_ip_all_levels_and_invalid(self):
        assert mask_ip("192.168.1.50", "none") == "192.168.1.50"
        assert mask_ip("", "partial") == ""
        assert mask_ip("not_an_ip", "partial") == "not_an_ip"
        assert mask_ip("192.168.1.50", "full") == "X.X.X.X"
        assert mask_ip("192.168.1.50", "subnet") == "192.168.1.X"
        assert mask_ip("192.168.1.50", "partial") == "X.X.X.50"

    def test_mask_mac_all_levels_and_invalid(self):
        assert mask_mac("00:11:22:33:44:55", "none") == "00:11:22:33:44:55"
        assert mask_mac("", "partial") == ""
        assert mask_mac("invalid_mac", "partial") == "invalid_mac"
        assert mask_mac("00:11:22:33:44:55", "full") == "XX:XX:XX:XX:XX:XX"
        assert mask_mac("00:11:22:33:44:55", "partial") == "XX:XX:XX:33:44:55"

    def test_mask_text_and_privacy_filter_disabled_enabled(self):
        sample_text = "Connection from 10.0.0.5 to 192.168.1.1 on port 80"
        masked = mask_text(sample_text, "full")
        assert "X.X.X.X" in masked

        # Disabled filter returns original
        pf_off = PrivacyFilter(enabled=False)
        assert pf_off.ip("10.0.0.1") == "10.0.0.1"
        assert pf_off.mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
        assert pf_off.text(sample_text) == sample_text

        # Enabled filter masks
        pf_on = PrivacyFilter(enabled=True, level="partial")
        assert pf_on.ip("10.0.0.1") == "X.X.X.1"
        assert pf_on.mac("00:11:22:33:44:55") == "XX:XX:XX:33:44:55"
        assert "X.X.X.5" in pf_on.text(sample_text)


class TestUtilsConsoleDeep:
    def test_console_alt_screen_and_clear_tty(self):
        with patch.object(sys.stdout, "isatty", return_value=True), \
             patch.object(sys.stdout, "write") as mock_write, \
             patch.object(sys.stdout, "flush"):
            enter_alt_screen()
            clear_screen()
            exit_alt_screen()
            assert mock_write.called

    def test_signal_handler(self):
        with patch("utils.console.exit_alt_screen") as mock_exit:
            with pytest.raises(SystemExit) as exc:
                _signal_handler(signal.SIGINT, None)
            assert exc.value.code == 0
            mock_exit.assert_called_once()


class TestUtilsPathHelpersDeep:
    def test_clean_path_input_quotes(self):
        assert clean_path_input("'test.pcap'") == "test.pcap"
        assert clean_path_input(' "test.pcap" ') == "test.pcap"
        assert clean_path_input("") == ""

    def test_resolve_path_error_handling(self):
        assert resolve_path("") is None

    def test_get_available_files_in_dir_errors(self):
        # Non-existent directory
        assert get_available_files_in_dir(Path("/non_existent_folder_12345")) == []

        # Permission error handling
        with patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "iterdir", side_effect=PermissionError):
            assert get_available_files_in_dir(Path("dummy")) == []

    def test_find_similar_helpers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_pcap = Path(tmpdir) / "sample_capture.pcap"
            sample_pcap.write_bytes(b"pcap_data")

            # 1. find_similar_pcap top match
            top_match = find_similar_pcap(Path(tmpdir) / "sampl_capture.pcap")
            assert top_match is not None
            assert top_match.name == "sample_capture.pcap"

            # 2. find_similar_pcap no match
            no_match = find_similar_pcap(Path(tmpdir) / "completely_unrelated_xyz.pcap", cutoff=0.9)
            assert no_match is None

            # 3. find_similar_json
            sample_json = Path(tmpdir) / "export_data.json"
            sample_json.write_text("{}", encoding="utf-8")
            json_matches = find_similar_json(Path(tmpdir) / "export_dat.json")
            assert len(json_matches) >= 1
            assert json_matches[0].name == "export_data.json"


class TestDetectionAlertsDeep:
    def test_alerts_counts_by_severity(self):
        mgr = AlertManager()
        mgr.add(AlertInfo(rule_name="R1", severity="CRITICAL", message="A1"))
        mgr.add(AlertInfo(rule_name="R2", severity="CRITICAL", message="A2"))
        mgr.add(AlertInfo(rule_name="R3", severity="HIGH", message="A3"))

        counts = mgr.get_counts_by_severity()
        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1

    def test_fingerprints_pruning_capacity(self):
        mgr = AlertManager(dedup_window=0.001)
        # Pre-populate fingerprints dict to simulate high volume (> 10,000)
        for i in range(10050):
            mgr.recent_fingerprints[f"fp_{i}"] = 1000.0  # Expired timestamp

        # Adding an alert triggers pruning
        alert = AlertInfo(rule_name="R_new", severity="INFO", message="New alert")
        mgr.add(alert)
        # Expired fingerprints pruned
        assert len(mgr.recent_fingerprints) < 10050
