"""
test_coverage_scan_view.py — Comprehensive rendering and branch coverage tests for tui/scan_view.py:
Progress panels, scan summaries, host tables, port/service breakdowns, long strings truncation,
and empty scan result states.
"""

from storage.models import ScanResult, HostInfo
from tui.scan_view import (
    display_scan_progress,
    display_scan_results,
    display_host_detail,
)


class TestScanViewRendering:
    def test_display_scan_progress_standard_and_warning_profiles(self):
        # 1. Standard scan profile (e.g. discovery)
        display_scan_progress(target="192.168.1.0/24", scan_type="discovery", scan_args="-sn")

        # 2. Aggressive / warning profile (e.g. stealth or aggressive)
        display_scan_progress(target="10.0.0.1", scan_type="aggressive")

        # 3. Custom profile without pre-configured constants
        display_scan_progress(target="10.0.0.5", scan_type="custom_type", scan_args="-sS -p 80")

    def test_display_scan_results_empty_and_populated(self):
        # 1. Empty scan result (0 hosts)
        empty_res = ScanResult(
            target="192.168.1.99",
            scan_type="discovery",
            scan_args="-sn",
            hosts_found=0,
            duration_sec=0.45,
            hosts=[],
        )
        display_scan_results(empty_res)

        # 2. Populated scan result with multiple hosts, long port lists, and services
        long_ports = list(range(1, 30))  # Summary will exceed 40 characters
        hosts = [
            HostInfo(
                ip_address="192.168.1.1",
                hostname="router.local",
                state="up",
                open_ports=long_ports,
                services={"80/tcp": "nginx 1.20", "443/tcp": "OpenSSL 1.1.1"},
                os_guess="Linux 5.4",
            ),
            HostInfo(
                ip_address="192.168.1.50",
                hostname="",  # N/A fallback
                state="up",
                open_ports=[22],
                services={},  # Fallback to "Open"
                os_guess="",  # Unknown fallback
            ),
            HostInfo(
                ip_address="192.168.1.100",
                hostname="desktop",
                state="up",
                open_ports=[],  # "None" open ports
                services={},
                os_guess="Windows 11",
            ),
        ]

        populated_res = ScanResult(
            target="192.168.1.0/24",
            scan_type="comprehensive",
            scan_args="-sS -sV -O",
            hosts_found=len(hosts),
            duration_sec=5.32,
            hosts=hosts,
        )
        display_scan_results(populated_res)

    def test_display_host_detail_services_and_ports(self):
        # 1. Host with populated services
        host_svc = HostInfo(
            ip_address="10.0.0.1",
            open_ports=[80, 443],
            services={"80/tcp": "Apache httpd 2.4.49", "443/tcp": "Apache SSL"},
        )
        display_host_detail(host_svc)

        # 2. Host with open ports but no service banner info
        host_nosvc = HostInfo(
            ip_address="10.0.0.2",
            open_ports=[21, 22, 23],
            services={},
        )
        display_host_detail(host_nosvc)
