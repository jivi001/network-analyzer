import os
import tempfile
from pathlib import Path
from unittest.mock import patch, call
import pytest

from utils.path_helpers import (
    clean_pcap_path_input,
    resolve_pcap_path,
    get_available_pcaps_in_dir,
    find_similar_pcap,
    find_similar_pcaps,
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

    def test_find_similar_pcap_single_and_multiple(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "test1.pcap").touch()
            (tmp_path / "test2.pcap").touch()
            (tmp_path / "testing.pcap").touch()

            # 1. Typo matching test1.pcap
            typo_path = tmp_path / "tast1.pcap"
            suggestions = find_similar_pcaps(typo_path, cutoff=0.4)
            assert len(suggestions) >= 1
            assert any(s.name == "test1.pcap" for s in suggestions)

            # 2. Case difference: TEST1.pcap
            case_path = tmp_path / "TEST1.pcap"
            suggestions_case = find_similar_pcaps(case_path)
            assert len(suggestions_case) >= 1
            assert suggestions_case[0].name == "test1.pcap"

            # 3. Extension difference: test1.pcapng
            ext_path = tmp_path / "test1.pcapng"
            suggestions_ext = find_similar_pcaps(ext_path)
            assert len(suggestions_ext) >= 1
            assert suggestions_ext[0].name == "test1.pcap"

            # 4. Completely unrelated name
            unrelated = tmp_path / "zebra_elephant_walrus.pcap"
            assert len(find_similar_pcaps(unrelated, cutoff=0.6)) == 0

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

    def test_prompt_typo_with_suggestion_1_selected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_file = tmp_path / "test1.pcap"
            real_file.touch()

            typo_input = str(tmp_path / "tast1.pcap")

            # First Prompt.ask returns typo path, second Prompt.ask returns "1"
            with patch("rich.prompt.Prompt.ask", side_effect=[typo_input, "1"]):
                result = prompt_pcap_path()
                assert result == str(real_file.resolve())

    def test_prompt_typo_with_multiple_suggestions_and_select_2(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_file1 = tmp_path / "test1.pcap"
            real_file2 = tmp_path / "test2.pcap"
            real_file1.touch()
            real_file2.touch()

            typo_input = str(tmp_path / "test3.pcap")

            # First Prompt.ask returns typo path, second Prompt.ask returns "2"
            with patch("rich.prompt.Prompt.ask", side_effect=[typo_input, "2"]):
                result = prompt_pcap_path()
                # Should return one of the existing test files
                assert result in (str(real_file1.resolve()), str(real_file2.resolve()))

    def test_prompt_invalid_selection_then_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_file = tmp_path / "test1.pcap"
            real_file.touch()

            typo_input = str(tmp_path / "tast1.pcap")

            # First typo, then invalid selection 99, then valid selection 1
            with patch("rich.prompt.Prompt.ask", side_effect=[typo_input, "99", "1"]):
                result = prompt_pcap_path()
                assert result == str(real_file.resolve())

    def test_prompt_suggestion_then_enter_new_valid_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_file1 = tmp_path / "test1.pcap"
            real_file2 = tmp_path / "other_capture.pcap"
            real_file1.touch()
            real_file2.touch()

            typo_input = str(tmp_path / "tast1.pcap")
            new_valid_input = str(real_file2)

            # First typo, then enters valid path to real_file2 directly
            with patch("rich.prompt.Prompt.ask", side_effect=[typo_input, new_valid_input]):
                result = prompt_pcap_path()
                assert result == str(real_file2.resolve())

    def test_prompt_suggestion_then_cancel_q(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_file = tmp_path / "test1.pcap"
            real_file.touch()

            typo_input = str(tmp_path / "tast1.pcap")

            # First typo, then user types "q" at the suggestion prompt
            with patch("rich.prompt.Prompt.ask", side_effect=[typo_input, "q"]):
                result = prompt_pcap_path()
                assert result == ""

    def test_prompt_no_suggestions_then_quit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            unrelated_input = str(tmp_path / "completely_unrelated_xyz_123.pcap")

            # First unrelated path with no suggestions, then user types "q"
            with patch("rich.prompt.Prompt.ask", side_effect=[unrelated_input, "q"]):
                result = prompt_pcap_path()
                assert result == ""
