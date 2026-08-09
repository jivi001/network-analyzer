"""
privacy.py — IP obfuscation for demos, recordings, and public broadcasts.
Masks IP addresses in terminal display without altering stored/exported data.
"""

import re


def mask_ip(ip: str, level: str = "partial") -> str:
    """
    Mask an IP address for privacy.
    
    Args:
        ip: The IP address string to mask.
        level: Masking level:
            - "partial": Show last octet only (X.X.X.42)
            - "full": Replace entirely (X.X.X.X)
            - "subnet": Show subnet only (192.168.1.X)
            - "none": No masking (return as-is)
    
    Returns:
        Masked IP address string.
    """
    if level == "none" or not ip:
        return ip

    parts = ip.split(".")
    if len(parts) != 4:
        return ip  # Not a valid IPv4, return as-is

    if level == "full":
        return "X.X.X.X"
    elif level == "subnet":
        return f"{parts[0]}.{parts[1]}.{parts[2]}.X"
    else:  # partial (default)
        return f"X.X.X.{parts[3]}"


def mask_mac(mac: str, level: str = "partial") -> str:
    """
    Mask a MAC address for privacy.
    
    Args:
        mac: The MAC address string (colon-separated).
        level: "partial" shows last 3 octets, "full" replaces all.
    
    Returns:
        Masked MAC address string.
    """
    if level == "none" or not mac:
        return mac

    parts = mac.split(":")
    if len(parts) != 6:
        return mac

    if level == "full":
        return "XX:XX:XX:XX:XX:XX"
    else:  # partial
        return f"XX:XX:XX:{parts[3]}:{parts[4]}:{parts[5]}"


def mask_text(text: str, level: str = "partial") -> str:
    """
    Find and mask all IPv4 addresses in a text string.
    Useful for masking IPs in alert messages and log entries.
    
    Args:
        text: Text string potentially containing IP addresses.
        level: Masking level to apply.
    
    Returns:
        Text with all IPs masked.
    """
    ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"

    def replace_match(match):
        return mask_ip(match.group(1), level)

    return re.sub(ip_pattern, replace_match, text)


class PrivacyFilter:
    """
    Configurable privacy filter for the entire application.
    Set once, applied consistently across all TUI output.
    """

    def __init__(self, enabled: bool = False, level: str = "partial"):
        self.enabled = enabled
        self.level = level

    def ip(self, ip_address: str) -> str:
        """Filter an IP address."""
        if not self.enabled:
            return ip_address
        return mask_ip(ip_address, self.level)

    def mac(self, mac_address: str) -> str:
        """Filter a MAC address."""
        if not self.enabled:
            return mac_address
        return mask_mac(mac_address, self.level)

    def text(self, text: str) -> str:
        """Filter all IPs in a text string."""
        if not self.enabled:
            return text
        return mask_text(text, self.level)
