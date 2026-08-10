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


ALLOWED_SCAN_TYPES = set(SCAN_TYPES.keys())


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

    def validate_scan_type(self, scan_type: str) -> str:
        """Ensure scan type is in the strict allowlist."""
        st = (scan_type or "").strip().lower()
        if st not in ALLOWED_SCAN_TYPES:
            raise ValueError(f"Unknown scan profile: '{scan_type}'. Allowed profiles: {sorted(ALLOWED_SCAN_TYPES)}")
        return st

    def _get_scan_args(self, scan_type: str) -> str:
        # Check config overrides first
        custom_arg = self.config.get(f"{scan_type}_scan") or self.config.get(scan_type)
        if custom_arg and isinstance(custom_arg, str):
            args = custom_arg
        else:
            scan_def = SCAN_TYPES.get(scan_type, SCAN_TYPES.get("top_ports", {}))
            args = scan_def.get("args", "-sS --top-ports 1000") if isinstance(scan_def, dict) else "-sS --top-ports 1000"

        if self.timeout and isinstance(self.timeout, (int, float)) and self.timeout > 0:
            if "--host-timeout" not in args:
                args = f"{args} --host-timeout {int(self.timeout)}s"
        return args

    def scan(self, target: str, scan_type: str = "top_ports") -> ScanResult:
        """Execute Nmap scan for any allowed scan profile."""
        scan_type = self.validate_scan_type(scan_type)
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

    # Backward compatibility wrappers
    def ping_sweep(self, target: str) -> List[HostInfo]:
        """Discovers live hosts (-sn)."""
        res = self.scan(target, "discovery")
        return res.hosts

    def port_scan(self, target: str, scan_type: str = "top_ports") -> ScanResult:
        """Port scan with service detection."""
        return self.scan(target, scan_type)

    def full_scan(self, target: str) -> ScanResult:
        """Service version + OS detection (-sS -sV -O)."""
        return self.scan(target, "comprehensive")

    def stealth_scan(self, target: str) -> ScanResult:
        """Slow evasive scan (-sS -T2)."""
        return self.scan(target, "stealth")

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
                    port_info = nm[host][proto][port]
                    port_state = port_info.get("state", "")
                    if port_state in ("open", "open|filtered"):
                        service_name = port_info.get("name", "")
                        product = port_info.get("product", "")
                        version = port_info.get("version", "")
                        extrainfo = port_info.get("extrainfo", "")

                        details = [p for p in [product, version, extrainfo] if p]
                        details_str = " ".join(details).strip()
                        svc_desc = f"{service_name} ({details_str})" if details_str else service_name
                        svc_desc = svc_desc.strip() or "unknown"

                        port_str = f"{port}/{proto}"
                        open_ports.append(f"{port_str} [{svc_desc}]")
                        services[port_str] = svc_desc

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
