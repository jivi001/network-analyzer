"""
models.py — Standardized Data Models for my-sentinel.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class PacketInfo:
    """Structured representation of a decoded network packet."""

    id: int = 0
    timestamp: float = 0.0  # Unix epoch timestamp for calculations
    timestamp_str: str = ""  # Formatted time string e.g. "19:04:12.123"
    date_str: str = ""

    # Network & Data Link layer
    src_ip: str = ""
    dst_ip: str = ""
    src_mac: str = ""
    dst_mac: str = ""

    # Transport layer
    protocol: str = "Other"
    src_port: int = 0
    dst_port: int = 0
    flags: list = field(default_factory=list)
    flags_raw: str = ""

    # Metadata
    length: int = 0
    service: str = "-"
    info: str = ""
    ttl: int = 0

    # Protocol-specific fields
    dns_query: str = ""
    dns_type: str = ""
    old_mac: str = ""
    new_mac: str = ""

    # Raw packet object reference
    raw_packet: Optional[Any] = None


@dataclass
class AlertInfo:
    """A threat detection alert."""

    id: int = 0
    timestamp: float = 0.0
    timestamp_str: str = ""
    severity: str = "INFO"  # INFO, WARNING, HIGH, CRITICAL
    rule_name: str = ""
    message: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    session_id: int = 0


@dataclass
class SessionInfo:
    """A capture or scan session record."""

    id: int = 0
    session_type: str = ""  # "capture", "scan", "pcap_analysis"
    start_time: str = ""
    end_time: str = ""
    packet_count: int = 0
    total_bytes: int = 0
    alert_count: int = 0
    interface: str = ""
    filter_applied: str = ""
    status: str = "active"  # active, completed, interrupted
    target: str = ""  # For scans: target IP/subnet


@dataclass
class HostInfo:
    """A discovered network host."""

    id: int = 0
    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    open_ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    os_guess: str = ""
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""  # "nmap", "capture", "manual"
    packet_count: int = 0
    byte_count: int = 0
    state: str = "up"  # up, down, unknown


@dataclass
class ScanResult:
    """Results from an Nmap scan."""

    id: int = 0
    session_id: int = 0
    target: str = ""
    scan_type: str = ""
    scan_args: str = ""
    hosts_found: int = 0
    hosts: List[HostInfo] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    duration_sec: float = 0.0
    raw_output: str = ""


@dataclass
class StatsSnapshot:
    """A point-in-time snapshot of capture statistics."""

    total_packets: int = 0
    total_bytes: int = 0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    avg_packet_size: float = 0.0
    unique_src_hosts: int = 0
    unique_dst_hosts: int = 0
    unique_hosts_total: int = 0
    protocol_counts: dict = field(default_factory=dict)
    protocol_percentages: dict = field(default_factory=dict)
    top_talkers: list = field(default_factory=list)  # list of dicts [{'ip': ..., 'bytes': ..., 'packets': ...}]
    elapsed_seconds: float = 0.0
    alert_count: int = 0


@dataclass
class DetectionRule:
    """A parsed YAML threat detection rule."""

    name: str = ""
    description: str = ""
    severity: str = "WARNING"
    enabled: bool = True
    match: dict = field(default_factory=dict)
    action: dict = field(default_factory=dict)


@dataclass
class WhoisInfo:
    """IP Whois lookup result."""

    ip: str = ""
    asn: str = ""
    asn_description: str = ""
    country: str = ""
    network_name: str = ""
    network_cidr: str = ""
    org: str = ""
    abuse_email: str = ""
    lookup_time: str = ""
