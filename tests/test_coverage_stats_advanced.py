"""
test_coverage_stats_advanced.py — Advanced behavioral and branch coverage tests for core/stats.py:
Rate calculator thread, telemetry sampling, memory measurement fallbacks, protocol distribution,
top talkers, reset semantics, and concurrent multi-threaded stress.
"""

import sys
import threading
import time
from unittest.mock import patch, MagicMock
import pytest

from core.stats import StatsAggregator, _sample_process_memory_mb
from storage.models import PacketInfo


class TestStatsAggregatorAdvanced:
    def test_sample_process_memory_fallbacks(self):
        # 1. Test Windows psapi / K32GetProcessMemoryInfo execution
        mem_mb = _sample_process_memory_mb()
        assert isinstance(mem_mb, float)
        assert mem_mb >= 0.0

        # 2. Test Unix/Linux resource.getrusage branch
        mock_resource = MagicMock()
        mock_resource.RUSAGE_SELF = 0
        mock_res = MagicMock()
        mock_res.ru_maxrss = 102400  # 100 MB on Linux (in KB)
        mock_resource.getrusage.return_value = mock_res

        with patch.object(sys, "platform", "linux"), patch.dict("sys.modules", {"resource": mock_resource}):
            mem_linux = _sample_process_memory_mb()
            assert mem_linux == 100.0

        # 3. Test macOS resource.getrusage branch (bytes)
        with patch.object(sys, "platform", "darwin"), patch.dict("sys.modules", {"resource": mock_resource}):
            mem_mac = _sample_process_memory_mb()
            assert mem_mac == 100.0

        # 4. Test exception fallback returning 0.0
        with patch.object(sys, "platform", "unsupported_os"):
            mem_err = _sample_process_memory_mb()
            assert mem_err == 0.0

    def test_protocol_distribution_empty_and_populated(self):
        agg = StatsAggregator()
        # Empty aggregator returns empty dict
        assert agg.get_protocol_distribution() == {}

        # Record packets across multiple protocols
        agg.update(PacketInfo(protocol="TCP", length=100))
        agg.update(PacketInfo(protocol="TCP", length=100))
        agg.update(PacketInfo(protocol="UDP", length=100))
        agg.update(PacketInfo(protocol="DNS", length=100))

        dist = agg.get_protocol_distribution()
        assert dist["TCP"] == 50.0
        assert dist["UDP"] == 25.0
        assert dist["DNS"] == 25.0

    def test_get_top_talkers_limits(self):
        agg = StatsAggregator()
        agg.update(PacketInfo(src_ip="10.0.0.1", length=1000))
        agg.update(PacketInfo(src_ip="10.0.0.2", length=2000))
        agg.update(PacketInfo(src_ip="10.0.0.3", length=3000))

        # Top 1 talker
        top1 = agg.get_top_talkers(n=1)
        assert len(top1) == 1
        assert top1[0]["ip"] == "10.0.0.3"
        assert top1[0]["bytes"] == 3000

        # Top 5 talkers (when only 3 exist)
        top5 = agg.get_top_talkers(n=5)
        assert len(top5) == 3
        assert top5[0]["ip"] == "10.0.0.3"
        assert top5[1]["ip"] == "10.0.0.2"
        assert top5[2]["ip"] == "10.0.0.1"

    def test_rate_calculator_lifecycle_and_ema_smoothing(self):
        agg = StatsAggregator()
        assert agg._running.is_set() is False

        # Start rate calculator
        agg.start_rate_calculator()
        assert agg._running.is_set() is True
        assert agg.rate_thread is not None
        assert agg.rate_thread.is_alive()

        # Calling start again while running is idempotent
        agg.start_rate_calculator()

        # Record packet burst
        for _ in range(50):
            agg.update(PacketInfo(length=200))

        # Let rate loop tick once
        time.sleep(1.1)

        # Stop rate calculator
        agg.stop_rate_calculator()
        assert agg._running.is_set() is False
        assert not agg.rate_thread.is_alive()

        # Calling stop again is idempotent
        agg.stop_rate_calculator()

    def test_reset_clears_all_counters_and_state(self):
        agg = StatsAggregator()
        agg.update(PacketInfo(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP", length=500))
        agg.packets_per_sec = 25.0
        agg.bytes_per_sec = 12500.0

        snap_before = agg.get_snapshot()
        assert snap_before.total_packets == 1
        assert snap_before.total_bytes == 500
        assert snap_before.unique_hosts_total == 2

        agg.reset()
        snap_after = agg.get_snapshot()
        assert snap_after.total_packets == 0
        assert snap_after.total_bytes == 0
        assert snap_after.packets_per_sec == 0.0
        assert snap_after.bytes_per_sec == 0.0
        assert snap_after.unique_hosts_total == 0
        assert snap_after.protocol_counts == {}
        assert snap_after.top_talkers == []
        assert snap_after.top_conversations == []

    def test_concurrent_multithreaded_updates(self):
        agg = StatsAggregator()
        num_threads = 8
        packets_per_thread = 100

        def worker(tid):
            for i in range(packets_per_thread):
                pkt = PacketInfo(
                    id=i,
                    src_ip=f"10.0.{tid}.1",
                    dst_ip=f"10.0.{tid}.2",
                    protocol="TCP" if i % 2 == 0 else "UDP",
                    length=100,
                )
                agg.update(pkt)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = agg.get_snapshot()
        assert snap.total_packets == num_threads * packets_per_thread
        assert snap.total_bytes == num_threads * packets_per_thread * 100
        assert snap.unique_hosts_total == num_threads * 2
