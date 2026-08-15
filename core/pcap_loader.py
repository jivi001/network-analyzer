import os
import logging
from typing import List
from scapy.all import PcapReader
from storage.models import PacketInfo, StatsSnapshot
from core.processor import process_packet
from core.stats import StatsAggregator

logger = logging.getLogger(__name__)


class PcapLoader:
    """PCAP File Loader and Analyzer — streaming, constant-memory."""

    def __init__(self):
        self.packets: List[PacketInfo] = []
        self.stats = StatsAggregator()

    def validate_file(self, filepath: str) -> bool:
        """Checks if the file exists and has a valid PCAP extension."""
        if not os.path.isfile(filepath):
            return False
        return filepath.lower().endswith(('.pcap', '.pcapng', '.cap'))

    def load(self, filepath: str) -> List[PacketInfo]:
        """Stream-loads a .pcap/.pcapng file one packet at a time.

        Memory scales with the number of decoded PacketInfo objects retained
        (for downstream display/analysis), NOT with the raw PCAP file size.
        Raw Scapy packet objects are released after decoding.
        """
        if not self.validate_file(filepath):
            raise FileNotFoundError(f"Invalid or missing PCAP file: {filepath}")

        self.packets.clear()
        self.stats.reset()

        try:
            packet_id = 1
            with PcapReader(filepath) as reader:
                for raw_pkt in reader:
                    pkt_info = process_packet(raw_pkt, packet_id)
                    self.packets.append(pkt_info)
                    self.stats.update(pkt_info)
                    packet_id += 1
            return self.packets
        except Exception as e:
            raise RuntimeError(f"Failed to load PCAP file '{filepath}': {e}")

    def get_stats(self) -> StatsSnapshot:
        """Aggregates stats from loaded packets."""
        return self.stats.get_snapshot()

    def get_packet_count(self) -> int:
        """Returns the total number of loaded packets."""
        return len(self.packets)

