import os
from typing import List
from scapy.all import rdpcap
from storage.models import PacketInfo, StatsSnapshot
from core.processor import process_packet
from core.stats import StatsAggregator

class PcapLoader:
    """PCAP File Loader and Analyzer."""

    def __init__(self):
        self.packets: List[PacketInfo] = []
        self.stats = StatsAggregator()

    def validate_file(self, filepath: str) -> bool:
        """Checks if the file exists and has a valid PCAP extension."""
        if not os.path.isfile(filepath):
            return False
        return filepath.lower().endswith(('.pcap', '.pcapng', '.cap'))

    def load(self, filepath: str) -> List[PacketInfo]:
        """Loads a .pcap/.pcapng file and decodes all packets."""
        if not self.validate_file(filepath):
            raise FileNotFoundError(f"Invalid or missing PCAP file: {filepath}")

        self.packets.clear()
        self.stats.reset()
        
        try:
            raw_packets = rdpcap(filepath)
            packet_id = 1
            for raw_pkt in raw_packets:
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
