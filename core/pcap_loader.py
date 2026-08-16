import os
import logging
from typing import List, Optional
from scapy.all import PcapReader
from storage.models import PacketInfo, StatsSnapshot
from core.processor import process_packet
from core.stats import StatsAggregator

logger = logging.getLogger(__name__)


class PcapLoader:
    """Offline PCAP File Forensics & Analyzer — streaming, constant-memory."""

    def __init__(self):
        self.packets: List[PacketInfo] = []
        self.stats = StatsAggregator()
        self.first_timestamp: Optional[float] = None
        self.last_timestamp: Optional[float] = None

    def validate_file(self, filepath: str) -> None:
        """Validates PCAP file presence, readability, and content size."""
        if not filepath or not isinstance(filepath, str):
            raise ValueError("PCAP file path cannot be empty.")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: '{filepath}'")
        if not os.path.isfile(filepath):
            raise ValueError(f"Path is a directory, not a PCAP file: '{filepath}'")
        if os.path.getsize(filepath) == 0:
            raise ValueError(f"PCAP file is empty (0 bytes): '{filepath}'")

    def load(self, filepath: str) -> List[PacketInfo]:
        """
        Stream-loads a .pcap/.pcapng/.cap file one packet at a time.
        Preserves constant RAM footprint by decoding raw Scapy packets on the fly.
        """
        self.validate_file(filepath)

        self.packets.clear()
        self.stats.reset()
        self.first_timestamp = None
        self.last_timestamp = None

        try:
            packet_id = 1
            with PcapReader(filepath) as reader:
                for raw_pkt in reader:
                    pkt_info = process_packet(raw_pkt, packet_id)
                    if pkt_info is not None:
                        self.packets.append(pkt_info)
                        self.stats.update(pkt_info)
                        if self.first_timestamp is None:
                            self.first_timestamp = pkt_info.timestamp
                        self.last_timestamp = pkt_info.timestamp
                        packet_id += 1
            return self.packets
        except Exception as e:
            err_msg = str(e).lower()
            if "bad magic" in err_msg or "not a pcap" in err_msg or "not a supported capture" in err_msg or "scapy_exception" in str(type(e)).lower():
                raise ValueError(f"Corrupt or invalid PCAP format in '{filepath}': {e}")
            raise RuntimeError(f"Failed to parse PCAP file '{filepath}': {e}")

    def get_stats(self) -> StatsSnapshot:
        """Aggregates forensic statistics with truthful PCAP capture duration and rates."""
        snapshot = self.stats.get_snapshot()

        # Compute forensic captured duration from real packet timestamps
        if self.first_timestamp is not None and self.last_timestamp is not None:
            capture_duration = max(0.0, self.last_timestamp - self.first_timestamp)
        else:
            capture_duration = 0.0

        snapshot.elapsed_seconds = capture_duration
        if capture_duration > 0 and snapshot.total_packets > 0:
            snapshot.packets_per_sec = snapshot.total_packets / capture_duration
            snapshot.bytes_per_sec = snapshot.total_bytes / capture_duration
        else:
            snapshot.packets_per_sec = float(snapshot.total_packets)
            snapshot.bytes_per_sec = float(snapshot.total_bytes)

        return snapshot

    def get_packet_count(self) -> int:
        """Returns the total number of loaded packets."""
        return len(self.packets)

