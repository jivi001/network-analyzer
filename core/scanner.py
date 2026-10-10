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
            # If formatted like an IPv4 (4 numeric octets), do not fallback to hostname
            if re.match(r"^\d+(\.\d+){3}$", target):
                raise ValueError(f"Invalid IPv4 address: '{target}'")

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

    # Strict exact sets of permitted Nmap options
    STANDALONE_FLAGS = frozenset({
        "-sS", "-sT", "-sU", "-sV", "-sP", "-sn", "-sA", "-sF", "-sN", "-sX",
        "-O", "-A", "-6",
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        "-Pn", "--open", "-v", "-vv",
        "--osscan-limit", "--osscan-guess",
    })

    OPTION_FLAGS = frozenset({
        "--top-ports",
        "--host-timeout",
        "--max-retries",
        "--min-rate",
        "--max-rate",
        "--version-intensity",
        "-p",
    })

    # Backward compatibility alias
    _SAFE_ARG_PREFIXES = STANDALONE_FLAGS | OPTION_FLAGS

    @staticmethod
    def _validate_port_spec(val: str) -> None:
        """Validate an Nmap port specification (e.g., '80,443', '1-1000', 'T:80,U:53', '-')."""
        if not val or not isinstance(val, str):
            raise ValueError("Port specification cannot be empty.")
        val = val.strip()
        if not val:
            raise ValueError("Port specification cannot be empty.")
        if val == "-":
            return  # Nmap shorthand for all ports 1-65535

        # Disallow shell metacharacters, whitespace, quotes, etc.
        if not re.match(r"^[0-9a-zA-Z,\-:]+$", val):
            raise ValueError(f"Port specification contains invalid characters: '{val}'")

        chunks = val.split(",")
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk:
                raise ValueError(f"Empty port specification chunk in '{val}'")
            if chunk == "-":
                continue

            # Strip optional protocol prefix: T:, U:, S:
            if len(chunk) > 2 and chunk[0].upper() in ("T", "U", "S") and chunk[1] == ":":
                chunk = chunk[2:]
                if not chunk:
                    raise ValueError(f"Missing port after protocol prefix in '{val}'")
                if chunk == "-":
                    continue

            # Single port number
            if re.match(r"^\d+$", chunk):
                p = int(chunk)
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port number {p} out of valid range (1-65535).")
            # Range p1-p2
            elif re.match(r"^(\d+)-(\d+)$", chunk):
                m = re.match(r"^(\d+)-(\d+)$", chunk)
                p1, p2 = int(m.group(1)), int(m.group(2))
                if not (1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 <= p2):
                    raise ValueError(f"Port range '{chunk}' is invalid or out of range (1-65535).")
            # Range -p2
            elif re.match(r"^-(\d+)$", chunk):
                p = int(chunk[1:])
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port range '{chunk}' out of valid range (1-65535).")
            # Range p1-
            elif re.match(r"^(\d+)-$", chunk):
                p = int(chunk[:-1])
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port range '{chunk}' out of valid range (1-65535).")
            else:
                raise ValueError(f"Invalid port specification segment: '{chunk}'")

    @classmethod
    def _validate_option_value(cls, opt: str, val: str) -> None:
        """Validate values for options requiring parameters."""
        if val is None or not str(val).strip():
            raise ValueError(f"Option '{opt}' requires a non-empty value.")
        val_str = str(val).strip()

        if opt == "-p":
            cls._validate_port_spec(val_str)
        elif opt == "--top-ports":
            if not re.match(r"^\d+$", val_str) or not (1 <= int(val_str) <= 65535):
                raise ValueError(f"Invalid value for --top-ports: '{val_str}'. Must be an integer 1-65535.")
        elif opt == "--host-timeout":
            m = re.match(r"^(\d+)(ms|[smh])?$", val_str, re.IGNORECASE)
            if not m or int(m.group(1)) <= 0:
                raise ValueError(f"Invalid value for --host-timeout: '{val_str}'. Must be a positive duration.")
        elif opt == "--max-retries":
            if not re.match(r"^\d+$", val_str) or not (0 <= int(val_str) <= 100):
                raise ValueError(f"Invalid value for --max-retries: '{val_str}'. Must be an integer 0-100.")
        elif opt == "--min-rate":
            if not re.match(r"^\d+$", val_str) or int(val_str) <= 0:
                raise ValueError(f"Invalid value for --min-rate: '{val_str}'. Must be a positive integer.")
        elif opt == "--max-rate":
            if not re.match(r"^\d+$", val_str) or int(val_str) <= 0:
                raise ValueError(f"Invalid value for --max-rate: '{val_str}'. Must be a positive integer.")
        elif opt == "--version-intensity":
            if not re.match(r"^\d$", val_str) or not (0 <= int(val_str) <= 9):
                raise ValueError(f"Invalid value for --version-intensity: '{val_str}'. Must be 0-9.")
        else:
            raise ValueError(f"Unrecognized option: '{opt}'")

    def _validate_scan_args(self, args: str) -> str:
        """Validate custom Nmap arguments against a strict allowlist.

        Replaces permissive prefix-matching with exact option allowlisting and
        strict value validation. Blocks shell injection, --script abuse, option
        lookalikes, and output file redirection.
        """
        import shlex
        if not args or not args.strip():
            return args

        tokens = shlex.split(args)
        i = 0
        n = len(tokens)
        seen_flags = set()

        while i < n:
            token = tokens[i]

            # 1. Standalone flag exact match
            if token in self.STANDALONE_FLAGS:
                seen_flags.add(token)
                i += 1
                continue

            # 2. Option flag with separate value: e.g. --top-ports 1000 or -p 80,443
            if token in self.OPTION_FLAGS:
                if i + 1 >= n:
                    raise ValueError(f"Nmap option '{token}' requires a value.")
                val = tokens[i + 1]
                self._validate_option_value(token, val)
                seen_flags.add(token)
                i += 2
                continue

            # 3. Option flag with '=' assignment: e.g. --top-ports=1000, --host-timeout=120s
            if "=" in token:
                opt, val = token.split("=", 1)
                if opt in self.OPTION_FLAGS:
                    self._validate_option_value(opt, val)
                    seen_flags.add(opt)
                    i += 1
                    continue
                else:
                    raise ValueError(
                        f"Nmap argument '{token}' is not in the safety allowlist."
                    )

            # 4. Attached -p flag: e.g. -p80,443, -p1-1000, -p-
            if token.startswith("-p") and len(token) > 2:
                # Disallow flags like -packet-trace, -privileged by validating remainder as port spec
                val = token[2:]
                try:
                    self._validate_port_spec(val)
                    seen_flags.add("-p")
                    i += 1
                    continue
                except ValueError as e:
                    raise ValueError(
                        f"Nmap argument '{token}' is not a valid option or port specification: {e}"
                    )

            # 5. Any unrecognized token (flags or orphan non-flag arguments)
            raise ValueError(
                f"Nmap argument '{token}' is not in the safety allowlist. "
                f"Use built-in scan types or approved flags."
            )

        # Validate mutually exclusive / incompatible combinations
        if "-p" in seen_flags and "--top-ports" in seen_flags:
            raise ValueError("Specifying both '-p' and '--top-ports' is not supported; they are mutually exclusive.")

        # Check for multiple mutually exclusive TCP scan types
        tcp_scans = {"-sS", "-sT", "-sA", "-sF", "-sN", "-sX"} & seen_flags
        if len(tcp_scans) > 1:
            raise ValueError(f"Cannot specify multiple TCP scan types simultaneously: {sorted(tcp_scans)}")

        # Check ping scan (-sn / -sP) combined with port scans
        ping_scans = {"-sn", "-sP"} & seen_flags
        port_scans = ({"-sS", "-sT", "-sU", "-sV", "-sA", "-sF", "-sN", "-sX"} | {"-p", "--top-ports"}) & seen_flags
        if ping_scans and port_scans:
            raise ValueError("Host discovery scan (-sn/-sP) cannot be combined with port scanning options.")

        return args


    def _get_scan_args(self, scan_type: str) -> str:
        # Check config overrides first
        custom_arg = self.config.get(f"{scan_type}_scan") or self.config.get(scan_type)
        if custom_arg and isinstance(custom_arg, str):
            args = self._validate_scan_args(custom_arg)
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
