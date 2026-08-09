import datetime
from typing import Optional, List

from storage.models import PacketInfo, AlertInfo, HostInfo
from utils.constants import get_protocol_color, get_severity_props
from utils.privacy import PrivacyFilter


def format_packet_row(
    packet: PacketInfo, privacy: Optional[PrivacyFilter] = None
) -> List[str]:
    """Format a PacketInfo into a list of strings for table row."""
    src = packet.src_ip
    dst = packet.dst_ip

    if privacy and privacy.enabled:
        src = privacy.ip(src)
        dst = privacy.ip(dst)

    src_str = f"{src}:{packet.src_port}" if packet.src_port else src
    dst_str = f"{dst}:{packet.dst_port}" if packet.dst_port else dst

    time_str = packet.timestamp_str or (
        datetime.datetime.fromtimestamp(packet.timestamp).strftime(
            "%H:%M:%S.%f"
        )[:-3]
        if isinstance(packet.timestamp, (int, float)) and packet.timestamp > 0
        else str(packet.timestamp)
    )

    proto_str = protocol_badge(packet.protocol)

    return [
        str(packet.id),
        time_str,
        src_str,
        dst_str,
        proto_str,
        str(packet.length),
        packet.service or "",
        truncate(packet.info or "", 60),
    ]


def format_alert_row(alert: AlertInfo) -> List[str]:
    """Format alert for table row."""
    time_str = alert.timestamp_str or (
        datetime.datetime.fromtimestamp(alert.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        if isinstance(alert.timestamp, (int, float)) and alert.timestamp > 0
        else str(alert.timestamp or "")
    )
    return [
        time_str,
        severity_badge(alert.severity),
        alert.rule_name,
        alert.src_ip or "",
        alert.dst_ip or "",
        truncate(alert.message, 80),
    ]


def format_host_row(host: HostInfo) -> List[str]:
    """Format host for table row."""
    first_seen = str(host.first_seen or "")
    last_seen = str(host.last_seen or "")
    return [
        host.ip_address,
        host.mac_address or "",
        host.hostname or "",
        str(len(host.open_ports)) if host.open_ports else "0",
        host.os_guess or "",
        first_seen,
        last_seen,
        host.source or "",
    ]


def protocol_badge(protocol: str) -> str:
    """Return Rich-styled protocol name."""
    if not protocol:
        return ""
    color = get_protocol_color(protocol)
    return f"[{color}]{protocol}[/{color}]"


def severity_badge(severity: str) -> str:
    """Return Rich-styled severity."""
    if not severity:
        return ""
    props = get_severity_props(severity)
    color = props.get("color", "white")
    return f"[{color} bold]{severity.upper()}[/{color} bold]"


def build_bar(value: float, max_value: float, width: int = 20) -> str:
    """ASCII bar chart."""
    if max_value <= 0:
        return "░" * width
    ratio = min(value / max_value, 1.0)
    filled_blocks = int(ratio * width)
    return "█" * filled_blocks + "░" * (width - filled_blocks)


def truncate(text: str, max_len: int = 50) -> str:
    """Truncate with ellipsis."""
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def format_elapsed(seconds: float) -> str:
    """Format seconds to HH:MM:SS."""
    td = datetime.timedelta(seconds=int(seconds))
    return str(td)
