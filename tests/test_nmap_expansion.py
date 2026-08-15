"""
tests/test_nmap_expansion.py

Comprehensive regression tests for expanded Nmap scan profiles, target validation,
timeout application, argument safety allowlisting, result normalization, and error recovery.
"""
import unittest
from unittest.mock import MagicMock, patch
from core.scanner import NetworkScanner, ALLOWED_SCAN_TYPES
from storage.models import ScanResult, HostInfo
from utils.constants import SCAN_TYPES


class NmapScannerExpansionTests(unittest.TestCase):
    """Test suite for all 11 predefined scan profiles and scanner robustness."""

    def setUp(self):
        self.mock_nm_patcher = patch("nmap.PortScanner")
        self.mock_nm_cls = self.mock_nm_patcher.start()
        self.mock_nm = MagicMock()
        self.mock_nm_cls.return_value = self.mock_nm

        self.scanner = NetworkScanner({"timeout": 120})

    def tearDown(self):
        self.mock_nm_patcher.stop()

    def test_all_11_profiles_and_aliases_defined(self):
        """Verify all 11 profiles and backward-compatibility aliases exist in ALLOWED_SCAN_TYPES."""
        expected_profiles = [
            "discovery", "top_ports", "service", "version", "os_detection",
            "comprehensive", "udp_top", "tcp_connect", "fast_discovery",
            "aggressive", "ipv6_discovery", "stealth",
            "quick", "port", "full"
        ]
        for prof in expected_profiles:
            self.assertIn(prof, ALLOWED_SCAN_TYPES, f"Profile '{prof}' missing from ALLOWED_SCAN_TYPES")
            self.assertIn(prof, SCAN_TYPES, f"Profile '{prof}' missing from constants.SCAN_TYPES")

    def test_argument_generation_and_timeout_application(self):
        """Verify Nmap arguments and timeout enforcement for every profile."""
        profile_expected_fragments = {
            "discovery": ["-sn", "--host-timeout 120s"],
            "fast_discovery": ["-sn", "-T4", "--host-timeout 120s"],
            "top_ports": ["-sS", "--top-ports 1000", "--host-timeout 120s"],
            "service": ["-sS", "-sV", "--top-ports 1000", "--host-timeout 120s"],
            "version": ["-sV", "--top-ports 1000", "--host-timeout 120s"],
            "os_detection": ["-sS", "-O", "--top-ports 1000", "--host-timeout 120s"],
            "comprehensive": ["-sS", "-sV", "-O", "--top-ports 1000", "--host-timeout 120s"],
            "udp_top": ["-sU", "--top-ports 100", "--host-timeout 120s"],
            "tcp_connect": ["-sT", "--top-ports 1000", "--host-timeout 120s"],
            "aggressive": ["-A", "--top-ports 1000", "--host-timeout 120s"],
            "ipv6_discovery": ["-6", "-sn", "--host-timeout 120s"],
            "stealth": ["-sS", "-T2", "--top-ports 100", "--host-timeout 120s"],
            "quick": ["-sn", "--host-timeout 120s"],
            "port": ["-sS", "--top-ports 1000", "--host-timeout 120s"],
            "full": ["-sS", "-sV", "-O", "--top-ports 1000", "--host-timeout 120s"],
        }

        for prof, fragments in profile_expected_fragments.items():
            args = self.scanner._get_scan_args(prof)
            for frag in fragments:
                self.assertIn(frag, args, f"Profile '{prof}' missing expected argument fragment '{frag}'. Got: '{args}'")

    def test_target_validation_ipv4_ipv6_cidr_and_hostnames(self):
        """Verify target validation accepts valid IPv4, IPv6, CIDR, and hostnames."""
        valid_targets = [
            "192.168.1.1",
            "10.0.0.0/24",
            "172.16.0.5",
            "::1",
            "fe80::1",
            "2001:db8::/64",
            "scanme.nmap.org",
            "router.local",
            "internal-server-1",
        ]
        for t in valid_targets:
            self.assertEqual(self.scanner.validate_target(t), t)

    def test_target_validation_rejects_injection_attempts(self):
        """Verify command injection attempts and malformed targets are rejected."""
        invalid_targets = [
            "",
            "   ",
            "-sS 192.168.1.1",
            "192.168.1.1; cat /etc/passwd",
            "192.168.1.1 | dir",
            "192.168.1.1 && whoami",
            "target`id`",
            "target$(whoami)",
            "192.168.1.999",
            "300.400.500.600",
        ]
        for t in invalid_targets:
            with self.assertRaises(ValueError, msg=f"Target '{t}' should have been rejected"):
                self.scanner.validate_target(t)

    def test_scan_type_allowlist_validation(self):
        """Verify invalid or unapproved scan types raise ValueError."""
        invalid_types = ["custom", "nuke", "all_ports", "hack", "; rm -rf", ""]
        for bad_type in invalid_types:
            with self.assertRaises(ValueError):
                self.scanner.validate_scan_type(bad_type)

    def test_custom_arg_safety_allowlist(self):
        """Verify safe custom config flags are allowed and dangerous flags are blocked."""
        # Safe flags
        safe_custom = "-sT -p 80,443 -T3 --open -v"
        self.assertEqual(self.scanner._validate_scan_args(safe_custom), safe_custom)

        # Dangerous flags (arbitrary NSE scripts, proxies, packet spoofing)
        dangerous_flags = [
            "--script vuln",
            "--script-args evil=1",
            "--proxies socks4://127.0.0.1:9050",
            "--spoof-mac 00:11:22:33:44:55",
            "--source-port 53",
            "-oN /tmp/out.txt",
        ]
        for flag in dangerous_flags:
            with self.assertRaises(ValueError, msg=f"Flag '{flag}' should be rejected"):
                self.scanner._validate_scan_args(flag)

    def test_result_normalization_and_enrichment(self):
        """Verify python-nmap output is normalized into HostInfo dataclasses with service details."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.50"]

        host_data = {
            "addresses": {"ipv4": "192.168.1.50", "mac": "00:0C:29:88:99:AA"},
            "osmatch": [{"name": "Linux 5.4 (Ubuntu 20.04)", "accuracy": "98"}],
            "tcp": {
                22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.2p1", "extrainfo": "Ubuntu-4ubuntu0.5"},
                80: {"state": "open", "name": "http", "product": "nginx", "version": "1.18.0", "extrainfo": ""},
                443: {"state": "closed", "name": "https"},
            },
        }
        host_mock = MagicMock()
        host_mock.__getitem__.side_effect = host_data.__getitem__
        host_mock.get.side_effect = host_data.get
        host_mock.state.return_value = "up"
        host_mock.all_protocols.return_value = ["tcp"]
        host_mock.hostname.return_value = "web-srv.local"
        mock_nm.__getitem__.return_value = host_mock

        hosts = self.scanner._parse_results(mock_nm)
        self.assertEqual(len(hosts), 1)
        h = hosts[0]
        self.assertEqual(h.ip_address, "192.168.1.50")
        self.assertEqual(h.mac_address, "00:0C:29:88:99:AA")
        self.assertEqual(h.hostname, "web-srv.local")
        self.assertEqual(h.state, "up")
        self.assertEqual(h.os_guess, "Linux 5.4 (Ubuntu 20.04)")
        self.assertEqual(len(h.open_ports), 2)  # 22 and 80 (443 was closed)
        self.assertIn("22/tcp [ssh (OpenSSH 8.2p1 Ubuntu-4ubuntu0.5)]", h.open_ports)
        self.assertIn("80/tcp [http (nginx 1.18.0)]", h.open_ports)
        self.assertEqual(h.services["22/tcp"], "ssh (OpenSSH 8.2p1 Ubuntu-4ubuntu0.5)")
        self.assertEqual(h.services["80/tcp"], "http (nginx 1.18.0)")

    def test_backward_compatibility_methods(self):
        """Verify backward compatibility wrapper methods execute correctly."""
        self.mock_nm.all_hosts.return_value = ["10.0.0.1"]
        host_data = {
            "addresses": {"ipv4": "10.0.0.1"},
            "osmatch": [],
            "tcp": {},
        }
        host_mock = MagicMock()
        host_mock.__getitem__.side_effect = host_data.__getitem__
        host_mock.get.side_effect = host_data.get
        host_mock.state.return_value = "up"
        host_mock.all_protocols.return_value = ["tcp"]
        host_mock.hostname.return_value = "router"
        self.mock_nm.__getitem__.return_value = host_mock

        # 1. ping_sweep
        hosts = self.scanner.ping_sweep("10.0.0.0/24")
        self.assertEqual(len(hosts), 1)

        # 2. port_scan
        res = self.scanner.port_scan("10.0.0.1")
        self.assertIsInstance(res, ScanResult)
        self.assertEqual(res.scan_type, "top_ports")

        # 3. full_scan
        res = self.scanner.full_scan("10.0.0.1")
        self.assertEqual(res.scan_type, "comprehensive")

        # 4. stealth_scan
        res = self.scanner.stealth_scan("10.0.0.1")
        self.assertEqual(res.scan_type, "stealth")

    def test_error_handling_when_nmap_scan_fails(self):
        """Verify scanner propagates PortScannerError gracefully without crashing."""
        self.mock_nm.scan.side_effect = RuntimeError("Host unreachable / network down")
        with self.assertRaises(RuntimeError):
            self.scanner.scan("192.168.1.1", "top_ports")


if __name__ == "__main__":
    unittest.main()
