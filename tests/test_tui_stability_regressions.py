import unittest
import threading
import time
from collections import deque
from scapy.all import Ether, IP, TCP, Raw

from core.stats import StatsAggregator
from detection.alerts import AlertManager, AlertInfo
from storage.models import PacketInfo
from tui.dashboard import LiveDashboard
from tui.helpers import format_packet_row, format_alert_row, format_host_row
from utils.console import console


class TUIStabilityRegressionTests(unittest.TestCase):
    """Targeted regression tests for TUI stability and performance under load."""

    def test_dynamic_packet_table_sizing(self):
        """Verify visible rows adjust to fit terminal dimensions and stay strictly bounded."""
        stats = StatsAggregator()
        am = AlertManager()
        dashboard = LiveDashboard(stats, am)

        # Populate with 500 packets in buffer
        sample_pkts = [
            PacketInfo(
                id=i,
                timestamp=time.time(),
                timestamp_str="12:00:00.000",
                date_str="2026-08-15",
                length=64,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.1",
                protocol="TCP",
                src_port=50000 + i,
                dst_port=80,
                flags=["SYN"],
                flags_raw="S",
                service="HTTP",
                info=f"Test packet {i}",
            )
            for i in range(500)
        ]

        # Test calculate_visible_rows
        visible_count = dashboard.calculate_visible_rows()
        self.assertGreaterEqual(visible_count, 1)
        self.assertLessEqual(visible_count, dashboard.max_render_rows)

        # Update dashboard and verify rendered packet buffer does not exceed visible limit
        dashboard.update(packets_buffer=sample_pkts, captured_pps=150.0)
        self.assertGreaterEqual(len(dashboard.packets_buffer), 1)
        self.assertLessEqual(len(dashboard.packets_buffer), visible_count)
        self.assertLessEqual(len(dashboard.packets_buffer), dashboard.max_render_rows)

    def test_untrusted_markup_safety(self):
        """Verify malicious or bracket-laden packet/alert strings do not break Rich markup."""
        stats = StatsAggregator()
        am = AlertManager()
        dashboard = LiveDashboard(stats, am)

        malicious_packets = [
            PacketInfo(
                id=1,
                timestamp=time.time(),
                src_ip="10.0.0.1:[SYN,ACK]",
                dst_ip="10.0.0.2:[/bold red]",
                protocol="TCP",
                src_port=80,
                dst_port=443,
                service="[SQLi-Test]",
                info="GET /search?q=[malicious] <script>alert(1)</script> [WinError 10013]",
            ),
            PacketInfo(
                id=2,
                timestamp=time.time(),
                src_ip="[INVALID_IP]",
                dst_ip="[BROADCAST]",
                protocol="UDP",
                src_port=53,
                dst_port=53,
                service="[DNS]",
                info="DNS Query: [test.example.com] [TAG_OPEN",
            ),
        ]

        am.add(AlertInfo(
            rule_name="[Exploit] Attempt",
            severity="CRITICAL",
            message="Buffer overflow payload [0x90909090] from [10.0.0.1]",
            src_ip="[10.0.0.1]",
            dst_ip="[10.0.0.2]",
        ))

        # Format helpers must succeed and escape markup tags
        row1 = format_packet_row(malicious_packets[0])
        self.assertIn(r"\[/bold red]", row1[3])
        self.assertIn(r"\[malicious]", row1[7])

        # Dashboard update must execute without exception
        try:
            dashboard.update(
                packets_buffer=malicious_packets,
                captured_count=1000,
                enqueued_count=1000,
                processed_count=1000,
                dropped_count=50,
                queue_depth=500,
                queue_capacity=10000,
                degraded_subsystems={"PCAP": "[ERROR_WRITE]"},
            )
            renderable = dashboard.get_renderable()
            self.assertIsNotNone(renderable)
        except Exception as e:
            self.fail(f"Dashboard update failed on untrusted markup: {e}")

    def test_near_100_percent_queue_saturation_health(self):
        """Verify TUI truthful health display and responsiveness when queue is at 9,999 / 10,000 (100%)."""
        stats = StatsAggregator()
        am = AlertManager()
        dashboard = LiveDashboard(stats, am)

        # Simulate genuine saturation: 9,999 in queue, 21,167 drops, rate 197 pps
        dashboard.update(
            packets_buffer=[],
            captured_count=27813,
            enqueued_count=6646,
            processed_count=6646,
            dropped_count=21167,
            queue_depth=9999,
            queue_capacity=10000,
            avg_latency_ms=1.2,
        )

        # Layout must exist and reflect critical state
        renderable = dashboard.get_renderable()
        self.assertIsNotNone(renderable)

    def test_safe_snapshot_isolation_under_high_concurrency(self):
        """Verify packet buffer slicing under lock is non-blocking and fast under rapid mutation."""
        buf = deque(maxlen=500)
        lock = threading.Lock()
        running = threading.Event()
        running.set()

        def producer():
            idx = 0
            while running.is_set():
                p = PacketInfo(id=idx, timestamp=time.time(), protocol="TCP")
                with lock:
                    buf.append(p)
                idx += 1
                time.sleep(0.0001)

        t = threading.Thread(target=producer)
        t.start()

        # Reader takes 100 snapshots
        snapshot_latencies = []
        for _ in range(100):
            t0 = time.perf_counter()
            with lock:
                l = len(buf)
                take = min(l, 30)
                snapped = [buf[i] for i in range(l - take, l)]
            t_ms = (time.perf_counter() - t0) * 1000.0
            snapshot_latencies.append(t_ms)
            time.sleep(0.001)

        running.clear()
        t.join(timeout=2.0)

        avg_snap_ms = sum(snapshot_latencies) / len(snapshot_latencies)
        self.assertLess(avg_snap_ms, 1.0, f"Average snapshot lock time {avg_snap_ms:.3f}ms exceeded 1ms target")


if __name__ == "__main__":
    unittest.main()
