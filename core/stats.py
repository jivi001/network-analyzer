import os
import sys
import threading
import time
from collections import Counter
from typing import Dict, List, Set, Any, Optional, Tuple
from storage.models import PacketInfo, StatsSnapshot


def _sample_process_memory_mb() -> float:
    """Lightweight sampled resident memory in MB across Windows and Unix."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            fn = getattr(ctypes.windll.kernel32, "K32GetProcessMemoryInfo", None) or getattr(
                ctypes.windll.psapi, "GetProcessMemoryInfo", None
            )
            if fn:
                fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
                fn.restype = wintypes.BOOL
                if fn(handle, ctypes.byref(counters), counters.cb):
                    return counters.WorkingSetSize / (1024 * 1024)
        else:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            return (usage / 1024.0) if sys.platform == "darwin" else (usage / 1024.0)
    except Exception:
        pass
    return 0.0


class StatsAggregator:
    """Thread-safe Statistics and System Telemetry Aggregator."""

    def __init__(self):
        self.lock = threading.RLock()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: Counter = Counter()
        self.ip_packets: Counter = Counter()
        self.ip_bytes: Counter = Counter()
        self.conversations: Counter = Counter()
        self.unique_src_ips: Set[str] = set()
        self.unique_dst_ips: Set[str] = set()
        self.unique_hosts: Set[str] = set()

        self.packets_per_sec: float = 0.0
        self.bytes_per_sec: float = 0.0
        self._last_packets: int = 0
        self._last_bytes: int = 0
        self._last_time: float = time.time()
        self._start_time: float = time.time()

        # Sampled system telemetry
        self.cpu_percent: float = 0.0
        self.memory_mb: float = 0.0
        self.thread_count: int = 1
        self._last_cpu_time: float = time.process_time()
        self._last_wall_time: float = time.time()

        self.rate_thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    def update(self, packet: PacketInfo):
        """Updates statistics with a new packet."""
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet.length
            self.protocol_counts[packet.protocol] += 1

            if packet.src_ip:
                self.ip_packets[packet.src_ip] += 1
                self.ip_bytes[packet.src_ip] += packet.length
                self.unique_src_ips.add(packet.src_ip)
                self.unique_hosts.add(packet.src_ip)

            if packet.dst_ip:
                self.ip_packets[packet.dst_ip] += 1
                self.ip_bytes[packet.dst_ip] += packet.length
                self.unique_dst_ips.add(packet.dst_ip)
                self.unique_hosts.add(packet.dst_ip)

            if packet.src_ip and packet.dst_ip:
                # Canonical pair
                pair = tuple(sorted([packet.src_ip, packet.dst_ip]))
                self.conversations[pair] += 1

    def get_snapshot(self) -> StatsSnapshot:
        """Returns a snapshot of the current statistics without long-held locks."""
        with self.lock:
            total_pkts = self.total_packets
            total_bytes = self.total_bytes
            pps = self.packets_per_sec
            bps = self.bytes_per_sec
            num_src = len(self.unique_src_ips)
            num_dst = len(self.unique_dst_ips)
            unique_total = len(self.unique_hosts)
            proto_counts = dict(self.protocol_counts)
            top_raw = self.ip_bytes.most_common(5)
            top_talkers = [
                {"ip": ip, "bytes": b, "packets": self.ip_packets[ip]}
                for ip, b in top_raw
            ]
            top_convs = [
                {"src": pair[0], "dst": pair[1], "packets": count}
                for pair, count in self.conversations.most_common(5)
            ]
            cpu_val = self.cpu_percent
            mem_val = self.memory_mb
            thr_val = self.thread_count

        # Heavy / derived calculations done outside lock
        elapsed = time.time() - self._start_time
        avg_size = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
        proto_pcts = (
            {proto: round((count / total_pkts) * 100.0, 1) for proto, count in proto_counts.items()}
            if total_pkts > 0 else {}
        )

        return StatsSnapshot(
            total_packets=total_pkts,
            total_bytes=total_bytes,
            packets_per_sec=pps,
            bytes_per_sec=bps,
            avg_packet_size=avg_size,
            unique_src_hosts=num_src,
            unique_dst_hosts=num_dst,
            unique_hosts_total=unique_total,
            protocol_counts=proto_counts,
            protocol_percentages=proto_pcts,
            top_talkers=top_talkers,
            top_conversations=top_convs,
            elapsed_seconds=elapsed,
            processing_pps=pps,
            cpu_percent=cpu_val,
            memory_mb=mem_val,
            thread_count=thr_val,
        )

    def reset(self):
        """Resets all statistics."""
        with self.lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts.clear()
            self.ip_packets.clear()
            self.ip_bytes.clear()
            self.conversations.clear()
            self.unique_src_ips.clear()
            self.unique_dst_ips.clear()
            self.unique_hosts.clear()
            self.packets_per_sec = 0.0
            self.bytes_per_sec = 0.0
            self._last_packets = 0
            self._last_bytes = 0
            self._last_time = time.time()
            self._start_time = time.time()

    def get_top_talkers(self, n: int = 5) -> List[Dict[str, Any]]:
        """Returns the top N talkers by packet count and byte volume."""
        with self.lock:
            top = self.ip_bytes.most_common(n)
            return [
                {"ip": ip, "bytes": b, "packets": self.ip_packets[ip]}
                for ip, b in top
            ]

    def get_protocol_distribution(self) -> Dict[str, float]:
        """Returns the protocol distribution as percentages."""
        with self.lock:
            if self.total_packets == 0:
                return {}
            total = self.total_packets
            counts = dict(self.protocol_counts)
        return {
            proto: round((count / total) * 100.0, 1)
            for proto, count in counts.items()
        }

    def start_rate_calculator(self):
        """Starts the background rate calculator thread."""
        if self._running.is_set():
            return
        self._running.set()
        self._last_time = time.time()
        self._last_packets = self.total_packets
        self._last_bytes = self.total_bytes
        self._last_cpu_time = time.process_time()
        self._last_wall_time = time.time()
        self.rate_thread = threading.Thread(target=self._calc_loop, daemon=True)
        self.rate_thread.start()

    def stop_rate_calculator(self):
        """Stops the rate calculator thread."""
        self._running.clear()
        if self.rate_thread and self.rate_thread.is_alive():
            self.rate_thread.join(timeout=2.0)

    def _calc_loop(self):
        while self._running.is_set():
            time.sleep(1.0)
            with self.lock:
                current_time = time.time()
                elapsed = current_time - self._last_time
                if elapsed > 0:
                    current_pps = (self.total_packets - self._last_packets) / elapsed
                    current_bps = (self.total_bytes - self._last_bytes) / elapsed

                    # Smooth rate using Exponential Moving Average (alpha=0.5)
                    self.packets_per_sec = (self.packets_per_sec * 0.5) + (current_pps * 0.5)
                    self.bytes_per_sec = (self.bytes_per_sec * 0.5) + (current_bps * 0.5)

                self._last_packets = self.total_packets
                self._last_bytes = self.total_bytes
                self._last_time = current_time

                # Sample CPU % and Memory
                now_cpu = time.process_time()
                now_wall = time.time()
                dt_wall = now_wall - self._last_wall_time
                dt_cpu = now_cpu - self._last_cpu_time
                if dt_wall > 0:
                    self.cpu_percent = min(100.0, max(0.0, (dt_cpu / dt_wall) * 100.0))
                self._last_wall_time = now_wall
                self._last_cpu_time = now_cpu

                self.memory_mb = _sample_process_memory_mb()
                self.thread_count = threading.active_count()
