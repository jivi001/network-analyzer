import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from utils.path_helpers import (
    clean_pcap_path_input,
    resolve_pcap_path,
    get_available_pcaps_in_dir,
    find_similar_pcap,
)
from tui.menu import prompt_pcap_path


class TestPathHelpers:
    """Test suite for path cleaning, normalization, and fuzzy PCAP matching."""

    def test_clean_pcap_path_input(self):
        # Plain path
        assert clean_pcap_path_input("test.pcap") == "test.pcap"
        # Whitespace
        assert clean_pcap_path_input("  test.pcap  ") == "test.pcap"
        # Quoted Windows path
        assert (
            clean_pcap_path_input('"D:\\Programs\\Security\\exports\\test1.pcap"')
            == "D:\\Programs\\Security\\exports\\test1.pcap"
        )
        # Single quoted path
        assert clean_pcap_path_input("'exports/test1.pcap'") == "exports/test1.pcap"
        # Empty string
        assert clean_pcap_path_input("") == ""

    def test_resolve_pcap_path(self):
        # Relative path
        p = resolve_pcap_path("exports/test1.pcap")
        assert p is not None
        assert p.name == "test1.pcap"

        # Windows style relative path
        p_win = resolve_pcap_path("exports\\test1.pcap")
        assert p_win is not None
        assert p_win.name == "test1.pcap"

        # Empty
        assert resolve_pcap_path("") is None
        assert resolve_pcap_path("   ") is None

    def test_find_similar_pcap_typo_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            target_real = tmp_path / "test1.pcap"
            target_real.touch()

            # 1. Typo: tast1.pcap
            typo_path = tmp_path / "tast1.pcap"
            suggestion = find_similar_pcap(typo_path)
            assert suggestion is not None
            assert suggestion.name == "test1.pcap"

            # 2. Case difference: TEST1.pcap
            case_path = tmp_path / "TEST1.pcap"
            suggestion = find_similar_pcap(case_path)
            assert suggestion is not None
            assert suggestion.name == "test1.pcap"

            # 3. Extension difference: test1.pcapng
            ext_path = tmp_path / "test1.pcapng"
            suggestion = find_similar_pcap(ext_path)
            assert suggestion is not None
            assert suggestion.name == "test1.pcap"

            # 4. Completely unrelated name
            unrelated = tmp_path / "zebra_elephant_walrus.pcap"
            assert find_similar_pcap(unrelated) is None

    def test_get_available_pcaps_in_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "cap1.pcap").touch()
            (tmp_path / "cap2.pcapng").touch()
            (tmp_path / "not_pcap.txt").touch()
            (tmp_path / "cap3.cap").touch()

            available = get_available_pcaps_in_dir(tmp_path)
            names = [f.name for f in available]

            assert len(available) == 3
            assert "cap1.pcap" in names
            assert "cap2.pcapng" in names
            assert "cap3.cap" in names
            assert "not_pcap.txt" not in names


class TestPromptPcapPathUX:
    """Test suite for interactive PCAP prompt UX flows."""

    def test_prompt_direct_valid_file(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            valid_path = tf.name

        try:
            with patch("rich.prompt.Prompt.ask", return_value=valid_path):
                result = prompt_pcap_path()
                assert result == str(Path(valid_path).resolve())
        finally:
            if os.path.exists(valid_path):
                os.remove(valid_path)

    def test_prompt_quoted_path(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            valid_path = tf.name

        try:
            quoted_input = f'"{valid_path}"'
            with patch("rich.prompt.Prompt.ask", return_value=quoted_input):
                result = prompt_pcap_path()
                assert result == str(Path(valid_path).resolve())
        finally:
            if os.path.exists(valid_path):
                os.remove(valid_path)

    def test_prompt_cancel_with_q(self):
        with patch("rich.prompt.Prompt.ask", return_value="q"):
            result = prompt_pcap_path()
            assert result == ""

    def test_prompt_typo_with_suggestion_accepted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_file = tmp_path / "test1.pcap"
            real_file.touch()

            typo_input = str(tmp_path / "tast1.pcap")

            # First Prompt.ask returns typo, Confirm.ask returns True
            with patch("rich.prompt.Prompt.ask", return_value=typo_input):
                with patch("rich.prompt.Confirm.ask", return_value=True):
                    result = prompt_pcap_path()
                    assert result == str(real_file.resolve())
