"""
constants.py - Port-service mappings, protocol names, color codes, and shared constants.
"""

# Well-known port to service name mappings
PORT_SERVICE_MAP = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Sub",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1434: "MSSQL-UDP",
    1521: "Oracle",
    1900: "SSDP/UPnP",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5353: "mDNS",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Cleartext (unencrypted) protocols that should be flagged
CLEARTEXT_PORTS = {20, 21, 23, 25, 69, 80, 110, 143, 161, 389, 514}

# Encrypted protocol ports (known safe)
ENCRYPTED_PORTS = {22, 443, 465, 587, 636, 993, 995, 8443}

# Protocol color coding for Rich TUI
PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "green",
    "ICMP": "yellow",
    "DNS": "blue",
    "ARP": "magenta",
    "HTTP": "red",
    "HTTPS": "bright_green",
    "SSH": "bright_cyan",
    "FTP": "bright_red",
    "Other": "white",
}

# Alert severity levels and their display properties
SEVERITY_LEVELS = {
    "INFO": {"color": "blue", "icon": "INFO", "priority": 0},
    "WARNING": {"color": "yellow", "icon": "WARN", "priority": 1},
    "HIGH": {"color": "red", "icon": "HIGH", "priority": 2},
    "CRITICAL": {"color": "bright_red bold", "icon": "CRIT", "priority": 3},
}

# TCP flag names
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

# Nmap scan type definitions and metadata
SCAN_TYPES = {
    "discovery": {
        "name": "Live Host Discovery",
        "args": "-sn",
        "description": "Ping sweep - discover live hosts without port scanning (-sn)",
        "requires_admin": False,
        "cost": "Low / Fast",
    },
    "fast_discovery": {
        "name": "Fast Discovery",
        "args": "-sn -T4",
        "description": "Accelerated ping sweep host discovery (-sn -T4)",
        "requires_admin": False,
        "cost": "Low / Very Fast",
    },
    "top_ports": {
        "name": "TCP Top Ports",
        "args": "-sS --top-ports 1000",
        "description": "SYN scan top 1000 TCP ports (-sS)",
        "requires_admin": True,
        "cost": "Moderate / Fast",
    },
    "service": {
        "name": "Service Detection",
        "args": "-sS -sV --top-ports 1000",
        "description": "SYN scan with service version identification (-sS -sV)",
        "requires_admin": True,
        "cost": "Moderate",
    },
    "version": {
        "name": "Version Enumeration",
        "args": "-sV --top-ports 1000",
        "description": "Probe open ports for service version details (-sV)",
        "requires_admin": False,
        "cost": "Moderate",
    },
    "os_detection": {
        "name": "OS Detection",
        "args": "-sS -O --top-ports 1000",
        "description": "TCP/IP stack fingerprinting for OS identification (-sS -O)",
        "requires_admin": True,
        "cost": "Moderate / Requires Admin",
    },
    "comprehensive": {
        "name": "Comprehensive Scan",
        "args": "-sS -sV -O --top-ports 1000",
        "description": "Combined SYN, version, and OS detection (-sS -sV -O)",
        "requires_admin": True,
        "cost": "High",
    },
    "udp_top": {
        "name": "UDP Top Ports",
        "args": "-sU --top-ports 100",
        "description": "UDP scan top 100 ports (-sU). Can be slow due to rate limiting.",
        "requires_admin": True,
        "cost": "High / Slow",
        "warning": "UDP scanning can take considerably longer than TCP scanning.",
    },
    "tcp_connect": {
        "name": "TCP Connect Scan",
        "args": "-sT --top-ports 1000",
        "description": "Full unprivileged TCP connect scan (-sT)",
        "requires_admin": False,
        "cost": "Moderate",
    },
    "aggressive": {
        "name": "Aggressive Assessment",
        "args": "-A --top-ports 1000",
        "description": "OS, version, script, and traceroute (-A). High traffic volume.",
        "requires_admin": True,
        "cost": "High / Loud",
        "warning": "Advanced scan — may generate significantly more traffic and take longer. Use only against authorized targets.",
    },
    "ipv6_discovery": {
        "name": "IPv6 Host Discovery",
        "args": "-6 -sn",
        "description": "Ping sweep over IPv6 (-6 -sn)",
        "requires_admin": False,
        "cost": "Low / Fast",
    },
    "stealth": {
        "name": "Stealth Scan",
        "args": "-sS -T2 --top-ports 100",
        "description": "Slow, evasive SYN scan top 100 ports (-sS -T2)",
        "requires_admin": True,
        "cost": "Slow / Low Traffic",
    },
    # Backward compatibility aliases
    "quick": {
        "name": "Quick Discovery",
        "args": "-sn",
        "description": "Ping sweep - discover live hosts only",
        "requires_admin": False,
        "cost": "Low / Fast",
    },
    "port": {
        "name": "Port Scan",
        "args": "-sS --top-ports 1000",
        "description": "SYN scan top 1000 ports",
        "requires_admin": True,
        "cost": "Moderate / Fast",
    },
    "full": {
        "name": "Full Scan",
        "args": "-sS -sV -O --top-ports 1000",
        "description": "Service version + OS detection",
        "requires_admin": True,
        "cost": "High",
    },
}

# Default dashboard refresh interval (milliseconds)
DASHBOARD_REFRESH_MS = 250

# Maximum packet buffer size for TUI display
DEFAULT_PACKET_BUFFER_SIZE = 500

# Rate calculation interval (seconds)
RATE_CALC_INTERVAL = 1.0

# Application metadata
APP_NAME = "my-sentinel"
APP_VERSION = "1.0.0"
APP_BANNER = r"""
  +----------------------------------------------+
  |              my-sentinel v1.0.0              |
  |      Network Traffic Analyzer & Scanner      |
  +----------------------------------------------+
"""


def resolve_service(sport: int, dport: int) -> str:
    """Translate source/destination port numbers into service names."""
    if dport in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[dport]
    if sport in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[sport]
    return f"Port {dport}" if dport else "Unknown"


def get_protocol_color(protocol: str) -> str:
    """Get the Rich color string for a protocol name."""
    return PROTOCOL_COLORS.get(protocol, "white")


def get_severity_props(severity: str) -> dict:
    """Get display properties for a severity level."""
    return SEVERITY_LEVELS.get(severity, SEVERITY_LEVELS["INFO"])


def format_bytes(byte_count: int) -> str:
    """Format byte count into human-readable string."""
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.1f} KB"
    elif byte_count < 1024 * 1024 * 1024:
        return f"{byte_count / (1024 * 1024):.1f} MB"
    else:
        return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"


def format_port_list(ports: list) -> str:
    """Format a list of port numbers into a compact string."""
    if not ports:
        return "-"
    if len(ports) <= 5:
        return ", ".join(str(p) for p in sorted(ports))
    return ", ".join(str(p) for p in sorted(ports)[:5]) + f" (+{len(ports) - 5})"
