import time
from typing import List
from storage.models import HostInfo, ScanResult
from utils.constants import SCAN_TYPES

try:
    import nmap
except ImportError:
    nmap = None


import ipaddress
import re
import time
from typing import List, Optional
from storage.models import HostInfo, ScanResult
from utils.constants import SCAN_TYPES

try:
    import nmap
except ImportError:
    nmap = None


class NetworkScanner:
    """Nmap Integration for Network Scanning."""

    def __init__(self, config: Optional[dict] = None):
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
        self.config = config or {}
        self.timeout = self.config.get("timeout", 300)

    def validate_target(self, target: str) -> str:
        """Validate target IP, CIDR, or hostname to prevent command injection."""
        target = target.strip()
        if not target:
            raise ValueError("Target cannot be empty.")
        
        # Try IP / CIDR
        try:
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
            return target
        except ValueError:
            pass

        # Hostname validation (alphanumeric, dots, hyphens)
        if re.match(r"^[a-zA-Z0-9.\-]+$", target) and not target.startswith("-"):
            return target
        raise ValueError(f"Invalid target address or hostname: '{target}'")

    def _get_scan_args(self, scan_type: str) -> str:
        # Check config overrides first
        custom_arg = self.config.get(f"{scan_type}_scan") or self.config.get(scan_type)
        if custom_arg and isinstance(custom_arg, str):
            args = custom_arg
        else:
            scan_def = SCAN_TYPES.get(scan_type, SCAN_TYPES.get("port", {}))
            args = scan_def.get("args", "-sS --top-ports 1000") if isinstance(scan_def, dict) else "-sS --top-ports 1000"

        if self.timeout and isinstance(self.timeout, (int, float)) and self.timeout > 0:
            if "--host-timeout" not in args:
                args = f"{args} --host-timeout {int(self.timeout)}s"
        return args

    def ping_sweep(self, target: str) -> List[HostInfo]:
        """Discovers live hosts (-sn)."""
        target = self.validate_target(target)
        args = self._get_scan_args("quick")
        self.nm.scan(hosts=target, arguments=args)
        return self._parse_results(self.nm)

    def port_scan(self, target: str, scan_type: str = "port") -> ScanResult:
        """Port scan with service detection."""
        target = self.validate_target(target)
        args = self._get_scan_args(scan_type)
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
        target = self.validate_target(target)
        args = self._get_scan_args("full")
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
        target = self.validate_target(target)
        args = self._get_scan_args("stealth")
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
