"""
tests/test_security_boundary_phase2.py

Phase 2 Security Boundary Hardening Regression Test Suite:
- Workstream A: Nmap argument validation (exact allowlisting, option value validation,
  lookalike rejection, combination rules, orphan argument rejection).
- Workstream B: Export path containment (path-aware containment, sibling directory prefix
  collision prevention, absolute path policy, system directory prohibitions, symlink escape rejection).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.scanner import NetworkScanner
from storage.exporter import Exporter


class TestNmapArgumentValidationPhase2(unittest.TestCase):
    """Workstream A: Exact allowlisting and option value validation for Nmap integration."""

    def setUp(self):
        self.mock_nm_patcher = patch("nmap.PortScanner")
        self.mock_nm_cls = self.mock_nm_patcher.start()
        self.mock_nm = MagicMock()
        self.mock_nm_cls.return_value = self.mock_nm
        self.scanner = NetworkScanner({"timeout": 120})

    def tearDown(self):
        self.mock_nm_patcher.stop()

    def test_allowed_standalone_flags(self):
        """Verify all legitimate standalone flags match exactly and are accepted."""
        standalone_flags = [
            "-sS", "-sT", "-sU", "-sV", "-sP", "-sn", "-sA", "-sF", "-sN", "-sX",
            "-O", "-A", "-6",
            "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
            "-Pn", "--open", "-v", "-vv",
            "--osscan-limit", "--osscan-guess",
        ]
        for flag in standalone_flags:
            self.assertEqual(self.scanner._validate_scan_args(flag), flag)

    def test_allowed_option_flags_and_values(self):
        """Verify legitimate option flags with valid values are accepted."""
        valid_combos = [
            "-p 80,443",
            "-p 1-1000",
            "-p-",
            "-p80",
            "-p80,443",
            "-p T:80,U:53",
            "--top-ports 100",
            "--top-ports=1000",
            "--host-timeout 120s",
            "--host-timeout=5m",
            "--host-timeout 300",
            "--max-retries 3",
            "--max-retries=2",
            "--min-rate 100",
            "--min-rate=50",
            "--max-rate 500",
            "--max-rate=1000",
            "--version-intensity 7",
            "--version-intensity=9",
            "-sT -p 80,443 -T3 --open -v",
        ]
        for combo in valid_combos:
            self.assertEqual(self.scanner._validate_scan_args(combo), combo)

    def test_rejects_prefix_lookalikes(self):
        """Verify option-prefix lookalikes are strictly rejected (DEF-006 fix)."""
        lookalikes = [
            "-Append-output",       # lookalike of -A
            "-Apple",               # lookalike of -A
            "-packet-trace",        # lookalike of -p
            "-privileged",          # lookalike of -p
            "-osscan",              # lookalike of -O
            "-output-format",       # lookalike of -O
            "-666",                 # lookalike of -6
            "-6evil",               # lookalike of -6
            "-T2evil",              # lookalike of -T2
            "--top-ports-evil",     # lookalike of --top-ports
            "--osscan-limit-evil",  # lookalike of --osscan-limit
        ]
        for flag in lookalikes:
            with self.assertRaises(ValueError, msg=f"Prefix lookalike '{flag}' must be rejected"):
                self.scanner._validate_scan_args(flag)

    def test_rejects_dangerous_and_unknown_flags(self):
        """Verify unapproved, dangerous, and output redirection flags are rejected."""
        unapproved_flags = [
            "--script vuln",
            "--script-args evil=1",
            "--stylesheet evil.xsl",
            "-oX scan.xml",
            "-oA scan_all",
            "-oN scan.txt",
            "-oG scan.grep",
            "--proxies socks4://127.0.0.1:9050",
            "--spoof-mac 00:11:22:33:44:55",
            "--source-port 53",
            "--data-length 25",
            "-badflag",
            "--unknown-option",
        ]
        for flag in unapproved_flags:
            with self.assertRaises(ValueError, msg=f"Flag '{flag}' must be rejected"):
                self.scanner._validate_scan_args(flag)

    def test_rejects_malformed_option_values(self):
        """Verify malformed, out-of-range, and injection values are rejected."""
        malformed_args = [
            "--top-ports 0",
            "--top-ports 70000",
            "--top-ports abc",
            "--top-ports -1",
            "--host-timeout 0",
            "--host-timeout -5s",
            "--host-timeout invalid",
            "--max-retries -1",
            "--max-retries 1000",
            "--max-retries abc",
            "--min-rate 0",
            "--min-rate -10",
            "--min-rate abc",
            "--max-rate 0",
            "--max-rate -100",
            "--version-intensity -1",
            "--version-intensity 10",
            "--version-intensity abc",
            "-p 80;whoami",
            "-p 80|ls",
            "-p 80$(id)",
            "-p 0",
            "-p 70000",
            "-p 1000-500",          # Inverted range
            "-p 1-70000",           # High port out of range
            "-p",                   # Missing value
            "--top-ports",          # Missing value
            "--host-timeout",       # Missing value
        ]
        for bad_arg in malformed_args:
            with self.assertRaises(ValueError, msg=f"Malformed arg '{bad_arg}' must be rejected"):
                self.scanner._validate_scan_args(bad_arg)

    def test_rejects_incompatible_option_combinations(self):
        """Verify mutually exclusive and contradictory option combinations are rejected."""
        incompatible = [
            "-p 80 --top-ports 1000",     # Both -p and --top-ports specified
            "-sS -sT",                    # Multiple TCP scan types
            "-sS -sA",                    # Multiple TCP scan types
            "-sn -p 80",                  # Ping sweep with port specification
            "-sn --top-ports 100",        # Ping sweep with port specification
            "-sn -sS",                    # Ping sweep with TCP scan
        ]
        for combo in incompatible:
            with self.assertRaises(ValueError, msg=f"Combo '{combo}' must be rejected"):
                self.scanner._validate_scan_args(combo)

    def test_rejects_orphan_non_flag_tokens(self):
        """Verify orphan non-flag tokens (target smuggling or trailing args) are rejected."""
        orphans = [
            "-sS 192.168.1.1",
            "-sS target.local",
            "-sS extra_arg",
            "unattached_token",
        ]
        for arg in orphans:
            with self.assertRaises(ValueError, msg=f"Orphan token '{arg}' must be rejected"):
                self.scanner._validate_scan_args(arg)


class TestExportPathContainmentPhase2(unittest.TestCase):
    """Workstream B: Path-aware containment, sibling collision, and symlink validation."""

    def setUp(self):
        self.exporter = Exporter()

    def test_valid_relative_paths_contained_in_export_dir(self):
        """Verify valid relative paths are resolved inside the permitted export directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.exporter.validate_export_path("report.csv", export_dir=tmp_dir)
            expected = str((Path(tmp_dir) / "report.csv").resolve())
            self.assertEqual(res, expected)
            self.assertTrue(Path(res).is_relative_to(Path(tmp_dir).resolve()))

    def test_traversal_sequences_rejected(self):
        """Verify .. directory traversal sequences are rejected."""
        bad_paths = [
            "../escaped.csv",
            "../../etc/passwd.csv",
            "..\\..\\windows\\system32.csv",
            "sub/../../escaped.json",
            "sub/..\\escaped.pcap",
        ]
        for p in bad_paths:
            with self.assertRaises(ValueError, msg=f"Path '{p}' should be rejected"):
                self.exporter.validate_export_path(p, export_dir="exports")

    def test_sibling_directory_prefix_collision_prevention(self):
        """Verify sibling directory collisions (exports_evil vs exports) are rejected."""
        with tempfile.TemporaryDirectory() as parent_tmp:
            base_exports = Path(parent_tmp) / "exports"
            base_exports.mkdir()
            evil_sibling = Path(parent_tmp) / "exports_evil"
            evil_sibling.mkdir()

            evil_target = str(evil_sibling / "loot.csv")

            # 1. Reject absolute target in evil sibling directory when custom export_dir is set
            with self.assertRaises(ValueError, msg="Sibling directory collision must be rejected"):
                self.exporter.validate_export_path(evil_target, export_dir=str(base_exports))

            # 2. Reject if allow_absolute=False
            with self.assertRaises(ValueError, msg="Sibling directory collision must be rejected with allow_absolute=False"):
                self.exporter.validate_export_path(evil_target, export_dir=str(base_exports), allow_absolute=False)

    def test_absolute_path_policy(self):
        """Verify allow_absolute controls whether safe absolute paths outside export_dir are allowed."""
        with tempfile.TemporaryDirectory() as safe_tmp:
            safe_target = os.path.join(safe_tmp, "packets.csv")

            # Default policy (allow_absolute=False): absolute path outside export_dir is rejected
            with self.assertRaises(ValueError):
                self.exporter.validate_export_path(safe_target)

            # Explicit opt-in at trusted boundary: allow_absolute=True permits safe external destination
            res = self.exporter.validate_export_path(safe_target, allow_absolute=True)
            self.assertEqual(res, str(Path(safe_target).resolve()))

            # Absolute path inside the configured export_dir is permitted by default
            inside_target = str((Path(safe_tmp) / "inside.csv").resolve())
            res_inside = self.exporter.validate_export_path(inside_target, export_dir=safe_tmp)
            self.assertEqual(res_inside, inside_target)

    def test_prohibited_system_directories_rejected(self):
        """Verify attempts to target root and system directories are rejected."""
        prohibited_paths = [
            "/etc/passwd.csv",
            "/malicious.csv",
            "/bin/sh.csv",
            "/root/loot.csv",
            "/usr/bin/python.csv",
            "C:\\Windows\\system32\\evil.csv",
            "C:\\Windows\\notepad.exe",
            "C:\\evil.csv",
        ]
        for p in prohibited_paths:
            with self.assertRaises(ValueError, msg=f"Prohibited path '{p}' must be rejected"):
                self.exporter.validate_export_path(p)

    def test_symlink_traversal_escape_rejected(self):
        """Verify symlink pointing outside export_dir is caught and rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_dir = Path(tmp_dir) / "exports"
            base_dir.mkdir()
            outside_dir = Path(tmp_dir) / "outside"
            outside_dir.mkdir()

            symlink_dir = base_dir / "symlink_dir"
            symlink_dir.symlink_to(outside_dir)

            escaped_target = "symlink_dir/stolen.csv"
            with self.assertRaises(ValueError, msg="Symlink escape must be rejected"):
                self.exporter.validate_export_path(escaped_target, export_dir=str(base_dir))

    def test_failures_occur_before_writing_or_directory_creation(self):
        """Verify failed validation does not create external directories or write files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            non_existent_evil = Path(tmp_dir) / "exports_unauthorized"
            evil_target = str(non_existent_evil / "test.csv")

            with self.assertRaises(ValueError):
                self.exporter.validate_export_path(evil_target, export_dir=os.path.join(tmp_dir, "exports"))

            # Ensure the unauthorized directory was NEVER created
            self.assertFalse(non_existent_evil.exists(), "Unauthorized directory must not be created on failure")

    def test_nested_sibling_directory_collision_rejected(self):
        """Verify deeply nested sibling directory collisions (exports_evil/nested/file.csv) are rejected."""
        with tempfile.TemporaryDirectory() as parent_tmp:
            base_exports = Path(parent_tmp) / "exports"
            base_exports.mkdir()
            evil_sibling = Path(parent_tmp) / "exports_evil"
            evil_sibling.mkdir()
            evil_nested = evil_sibling / "nested"
            evil_nested.mkdir()

            evil_target = str(evil_nested / "loot.csv")

            # Must be rejected with allow_absolute=False (default)
            with self.assertRaises(ValueError):
                self.exporter.validate_export_path(evil_target, export_dir=str(base_exports), allow_absolute=False)

            # Must also be rejected even with allow_absolute=True opt-in
            with self.assertRaises(ValueError):
                self.exporter.validate_export_path(evil_target, export_dir=str(base_exports), allow_absolute=True)


if __name__ == "__main__":
    unittest.main()
