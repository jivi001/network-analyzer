import time
from typing import List
from storage.models import HostInfo, ScanResult
from utils.constants import SCAN_TYPES

try:
    import nmap
except ImportError:
    nmap = None


class NetworkScanner:
    """Nmap Integration for Network Scanning."""

    def __init__(self):
        if nmap is None:
            raise ImportError(
                "python-nmap is not installed. Please install it to use NetworkScanner."
            )
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            raise RuntimeError(
                f"Failed to initialize Nmap PortScanner: {e}. Is Nmap installed in PATH?"
            )

    def ping_sweep(self, target: str) -> List[HostInfo]:
        """Discovers live hosts (-sn)."""
        scan_def = SCAN_TYPES.get("quick", {})
        args = scan_def.get("args", "-sn") if isinstance(scan_def, dict) else "-sn"
        self.nm.scan(hosts=target, arguments=args)
        return self._parse_results(self.nm)

    def port_scan(self, target: str, scan_type: str = "port") -> ScanResult:
        """Port scan with service detection."""
        scan_def = SCAN_TYPES.get(scan_type, SCAN_TYPES.get("port", {}))
        args = (
            scan_def.get("args", "-sS --top-ports 1000")
            if isinstance(scan_def, dict)
            else "-sS --top-ports 1000"
        )
        start_time = time.time()
        self.nm.scan(hosts=target, arguments=args)
        duration = time.time() - start_time
        hosts = self._parse_results(self.nm)
        return ScanResult(
            target=target,
            scan_type=scan_type,
            scan_args=args,
            hosts_found=len(hosts),
            hosts=hosts,
            duration_sec=duration,
        )

    def full_scan(self, target: str) -> ScanResult:
        """Service version + OS detection (-sV -O)."""
        scan_def = SCAN_TYPES.get("full", {})
        args = (
            scan_def.get("args", "-sV -O --top-ports 1000")
            if isinstance(scan_def, dict)
            else "-sV -O --top-ports 1000"
        )
        start_time = time.time()
        self.nm.scan(hosts=target, arguments=args)
        duration = time.time() - start_time
        hosts = self._parse_results(self.nm)
        return ScanResult(
            target=target,
            scan_type="full",
            scan_args=args,
            hosts_found=len(hosts),
            hosts=hosts,
            duration_sec=duration,
        )

    def stealth_scan(self, target: str) -> ScanResult:
        """Slow evasive scan (-sS -T2)."""
        scan_def = SCAN_TYPES.get("stealth", {})
        args = (
            scan_def.get("args", "-sS -T2 --top-ports 100")
            if isinstance(scan_def, dict)
            else "-sS -T2 --top-ports 100"
        )
        start_time = time.time()
        self.nm.scan(hosts=target, arguments=args)
        duration = time.time() - start_time
        hosts = self._parse_results(self.nm)
        return ScanResult(
            target=target,
            scan_type="stealth",
            scan_args=args,
            hosts_found=len(hosts),
            hosts=hosts,
            duration_sec=duration,
        )

    def _parse_results(self, nm) -> List[HostInfo]:
        """Parses python-nmap output into HostInfo dataclasses."""
        results = []
        for host in nm.all_hosts():
            mac = ""
            if "mac" in nm[host].get("addresses", {}):
                mac = nm[host]["addresses"]["mac"]

            state = nm[host].state()
            os_matches = nm[host].get("osmatch", [])
            os_name = os_matches[0]["name"] if os_matches else "Unknown"

            open_ports = []
            services = {}
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    if nm[host][proto][port]["state"] == "open":
                        service_name = nm[host][proto][port].get("name", "")
                        version = nm[host][proto][port].get("version", "")
                        port_str = f"{port}/{proto}"
                        open_ports.append(
                            f"{port_str} ({service_name} {version})".strip()
                        )
                        services[port_str] = f"{service_name} {version}".strip()

            hostname = nm[host].hostname() or ""

            results.append(
                HostInfo(
                    ip_address=host,
                    mac_address=mac,
                    hostname=hostname,
                    state=state,
                    os_guess=os_name,
                    open_ports=open_ports,
                    services=services,
                    source="nmap",
                )
            )
        return results
