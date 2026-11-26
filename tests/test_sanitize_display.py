"""
tests/test_sanitize_display.py

Regression tests for tui.helpers.sanitize_display().

Covers the terminal-rendering security conditions from the remediation
checklist (Phase 3A / Phase 4 - Terminal behavior):
  - safe conversion of untrusted objects (None, int, arbitrary objects)
  - Rich markup escaping (square brackets, [bold], [/tag])
  - C0 control-character removal (except TAB/LF/CR), DEL and ESC removal
  - ANSI CSI and OSC sequence neutralisation (incl. OSC 52 clipboard, OSC 8 hyperlink)
  - Unicode / readable text preservation
  - original data is not mutated
  - long input handled safely
  - rendered output does not execute markup and does not crash Rich
"""
import io
import unittest

from rich.console import Console

from tui.helpers import sanitize_display


class SanitizeDisplayTests(unittest.TestCase):
    """Verify sanitize_display() neutralises terminal-injection vectors."""

    def test_handles_none_and_unexpected_types(self):
        self.assertEqual(sanitize_display(None), "")
        self.assertEqual(sanitize_display(12345), "12345")
        # Arbitrary object converts to its repr without raising.
        out = sanitize_display(object())
        self.assertIsInstance(out, str)
        self.assertNotIn("\x1b", out)

    def test_escapes_rich_markup(self):
        out = sanitize_display("[bold red]evil[/bold red]")
        self.assertIn(r"\[bold red]", out)
        self.assertIn(r"\[/bold red]", out)
        # Bracket-only payload is escaped too.
        self.assertIn(r"\[malicious]", sanitize_display("[malicious] <script>"))

    def test_removes_c0_control_chars_but_keeps_tab_lf_cr(self):
        raw = "a\x00b\x01c\x1fd\x7fe"
        out = sanitize_display(raw)
        for ch in ("\x00", "\x01", "\x1f", "\x7f"):
            self.assertNotIn(ch, out)
        self.assertEqual(out, "abcde")
        # TAB, LF, CR are preserved for readable layout.
        self.assertEqual(sanitize_display("x\ty\nz\rw"), "x\ty\nz\rw")

    def test_removes_esc_and_ansi_csi(self):
        self.assertNotIn("\x1b", sanitize_display("safe\x1b[31mred"))
        self.assertNotIn("\x1b", sanitize_display("\x1b[2J\x1b[Hcleared"))

    def test_neutralises_osc52_clipboard(self):
        payload = "\x1b]52;c;ZHVtbWFjdA==\x07"
        out = sanitize_display(payload)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)  # BEL terminator removed (C0)

    def test_neutralises_osc8_hyperlink(self):
        payload = "\x1b]8;;http://evil\x1b\\click\x1b]8;;\x1b\\"
        out = sanitize_display(payload)
        self.assertNotIn("\x1b", out)

    def test_preserves_unicode_and_readable_text(self):
        text = "unicøde-tëst-日本語-Ω"
        self.assertEqual(sanitize_display(text), text)
        self.assertEqual(sanitize_display("normal.example.com"), "normal.example.com")

    def test_does_not_mutate_input(self):
        original = "[bold]keep[/bold]"
        sanitize_display(original)
        self.assertEqual(original, "[bold]keep[/bold]")  # unchanged

    def test_handles_long_input(self):
        out = sanitize_display("A" * 10000)
        self.assertEqual(len(out), 10000)

    def test_renders_safely_through_rich(self):
        """Escaped payload must render as literal text, not execute markup."""
        buf = io.StringIO()
        console = Console(file=buf, width=80)
        console.print("[bold]Safe[/bold] " + sanitize_display("[blink]evil[/blink]"))
        rendered = buf.getvalue()
        self.assertIn("Safe", rendered)
        self.assertIn("[blink]evil[/blink]", rendered)


if __name__ == "__main__":
    unittest.main()