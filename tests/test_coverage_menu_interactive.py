"""
test_coverage_menu_interactive.py — Interactive menu and prompt branch coverage tests for tui/menu.py:
Main menu selections, capture/scan settings prompts, PCAP/JSON path inputs, export configuration,
and settings toggles under simulated user input.
"""

from unittest.mock import patch
import pytest

from tui.menu import (
    show_main_menu,
    prompt_capture_settings,
    prompt_scan_settings,
    prompt_pcap_path,
    prompt_export_settings,
    prompt_json_import_path,
)


class TestMenuPromptsCoverage:
    def test_show_main_menu_choices(self):
        for choice in ["1", "2", "3", "4", "5", "6"]:
            with patch("rich.prompt.Prompt.ask", return_value=choice):
                assert show_main_menu() == choice

    def test_prompt_capture_settings(self):
        with patch("rich.prompt.Prompt.ask", side_effect=["Ethernet", "192.168.1.1", "tcp port 80"]):
            settings = prompt_capture_settings()
            assert settings["interface"] == "Ethernet"
            assert settings["target_ip"] == "192.168.1.1"
            assert settings["bpf_filter"] == "tcp port 80"

    def test_prompt_scan_settings_valid_and_cancel(self):
        # 1. Cancel choice 'Q'
        with patch("rich.prompt.Prompt.ask", return_value="Q"):
            assert prompt_scan_settings() is None

        # 2. Valid selection '2' (top_ports) with valid target
        with patch("rich.prompt.Prompt.ask", side_effect=["2", "192.168.1.1"]):
            scan_cfg = prompt_scan_settings()
            assert scan_cfg is not None
            assert scan_cfg["target"] == "192.168.1.1"
            assert scan_cfg["scan_type"] == "top_ports"

        # 3. Target input cancelled with empty input (Enter)
        with patch("rich.prompt.Prompt.ask", side_effect=["1", ""]):
            assert prompt_scan_settings() is None

    def test_prompt_export_settings(self):
        with patch("rich.prompt.Prompt.ask", side_effect=["CSV", "test_out.csv"]):
            res = prompt_export_settings()
            assert res["format"] == "csv"
            assert res["filename"] == "test_out.csv"

    def test_prompt_pcap_path_cancel_and_input(self):
        # 1. Cancel input
        with patch("rich.prompt.Prompt.ask", return_value="q"):
            assert prompt_pcap_path() == ""

        # 2. Non-existent path without suggestions
        with patch("rich.prompt.Prompt.ask", side_effect=["non_existent_xyz.pcap", "q"]):
            assert prompt_pcap_path() == ""

    def test_prompt_json_import_path_cancel(self):
        with patch("rich.prompt.Prompt.ask", return_value="q"):
            assert prompt_json_import_path() == ""
