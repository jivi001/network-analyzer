"""
test_unit_utils.py — Comprehensive unit tests for utils package:
privacy, privileges, constants, console, path_helpers.
"""

from pathlib import Path
import pytest

from utils.privacy import PrivacyFilter
from utils.privileges import check_privileges, check_nmap_installed, check_npcap_installed, run_all_checks
from utils.constants import get_protocol_color, get_severity_props, format_bytes
from utils.console import ScreenManager, ScreenState, clear_screen
from utils.path_helpers import (
    clean_path_input,
    resolve_path,
    get_available_files_in_dir,
    find_similar_files,
)


class TestPrivacyFilter:
    def test_ip_masking(self):
        pf = PrivacyFilter(enabled=True, level="partial")
        masked_v4 = pf.ip("192.168.1.100")
        assert masked_v4 != "192.168.1.100"
        assert masked_v4.startswith("X.X.X.")

        pf_disabled = PrivacyFilter(enabled=False)
        assert pf_disabled.ip("192.168.1.100") == "192.168.1.100"

    def test_mac_masking(self):
        pf = PrivacyFilter(enabled=True, level="partial")
        masked_mac = pf.mac("00:11:22:33:44:55")
        assert masked_mac != "00:11:22:33:44:55"
        assert masked_mac.startswith("XX:XX:XX:")

    def test_payload_scrubbing(self):
        pf = PrivacyFilter(enabled=True, level="partial")
        scrubbed = pf.text("Connected from 192.168.1.100 to server")
        assert "192.168.1.100" not in scrubbed


class TestPrivileges:
    def test_privilege_check_execution(self):
        res = check_privileges(require_exit=False)
        assert isinstance(res, bool)

    def test_check_nmap_and_npcap(self):
        nmap_avail = check_nmap_installed()
        assert isinstance(nmap_avail, bool)

        npcap_avail = check_npcap_installed()
        assert isinstance(npcap_avail, bool)

    def test_run_all_checks(self):
        checks = run_all_checks(require_admin=False)
        assert isinstance(checks, dict)
        assert "privileges" in checks
        assert "nmap" in checks
        assert "pcap" in checks


class TestConstantsAndFormatting:
    def test_format_bytes(self):
        assert format_bytes(0) == "0 B"
        assert format_bytes(512) == "512 B"
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1048576) == "1.0 MB"
        assert "GB" in format_bytes(1073741824)

    def test_protocol_color(self):
        assert get_protocol_color("TCP") is not None
        assert get_protocol_color("UDP") is not None
        assert get_protocol_color("UNKNOWN_PROTO") is not None

    def test_severity_props(self):
        crit = get_severity_props("CRITICAL")
        assert "color" in crit
        assert "red" in crit["color"]


class TestConsoleAndScreenManager:
    def test_screen_state_transitions(self):
        sm = ScreenManager()
        sm.set_state(ScreenState.MAIN_MENU)
        assert sm.current_state == ScreenState.MAIN_MENU

        sm.set_state(ScreenState.TASK_RUNNING)
        assert sm.current_state == ScreenState.TASK_RUNNING

        sm.set_state(ScreenState.TASK_COMPLETE)
        assert sm.current_state == ScreenState.TASK_COMPLETE


class TestPathHelpers:
    def test_clean_path_input(self):
        assert clean_path_input('  "D:\\test\\path.json"  ') == "D:\\test\\path.json"
        assert clean_path_input(" 'relative/path.pcap' ") == "relative/path.pcap"
        assert clean_path_input("") == ""

    def test_resolve_path(self):
        p = resolve_path("exports/test.json")
        assert p is not None
        assert isinstance(p, Path)
        assert resolve_path("") is None
