"""
test_coverage_traffic_lab_comprehensive.py — Comprehensive behavioral and branch coverage tests for traffic_lab.py:
TCP/UDP action dispatchers, HTTP/DNS mock clients, rate dispatched runners, error categorization,
validation invariants, and stats reporting loops.
"""

import socket
import threading
import time
from unittest.mock import patch, MagicMock
import pytest

from traffic_lab import (
    Counters,
    dns_query,
    http_get,
    do_internet_action,
    do_tcp_action,
    do_udp_action,
    rate_dispatched_runner,
    internet,
    local_or_lan,
    stats_loop,
    validate,
    MAX_DURATION,
    MAX_INTERNET_RATE,
    MAX_LAN_RATE,
    MAX_LOCAL_RATE,
)


class TestTrafficLabComprehensive:
    def test_http_get_scheme_enforcement_and_success(self):
        # Non-HTTPS endpoints must raise ValueError
        with pytest.raises(ValueError, match="Only HTTPS"):
            http_get("http://insecure.example.com")

        # Successful HTTPS chunked download
        with patch("http.client.HTTPSConnection") as mock_conn_cls:
            mock_conn = MagicMock()
            mock_resp = MagicMock()
            mock_resp.read.side_effect = [b"chunk_1_data", b"chunk_2_data", b""]
            mock_conn.getresponse.return_value = mock_resp
            mock_conn_cls.return_value = mock_conn

            total_bytes = http_get("https://example.com/test")
            assert total_bytes == len(b"chunk_1_data") + len(b"chunk_2_data")
            mock_conn.close.assert_called_once()

    def test_dns_query_packet_generation(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (b"\x00" * 64, ("1.1.1.1", 53))
            mock_sock_cls.return_value.__enter__.return_value = mock_sock

            rx_bytes = dns_query(("1.1.1.1", 53), hostname="test.example.com")
            assert rx_bytes == 64
            mock_sock.sendto.assert_called_once()

    def test_do_tcp_action_error_classification(self):
        c = Counters()

        # 1. Success
        with patch("socket.create_connection") as mock_conn:
            mock_s = MagicMock()
            mock_conn.return_value.__enter__.return_value = mock_s
            do_tcp_action("127.0.0.1", 8080, c)
            assert c.attempts == 1
            assert c.successes == 1

        # 2. Timeout
        with patch("socket.create_connection", side_effect=socket.timeout):
            do_tcp_action("127.0.0.1", 8080, c)
            assert c.attempts == 2
            assert c.timeouts == 1

        # 3. Connection Refused
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            do_tcp_action("127.0.0.1", 8080, c)
            assert c.attempts == 3
            assert c.refused == 1

        # 4. Other OSError
        with patch("socket.create_connection", side_effect=OSError("Network unreachable")):
            do_tcp_action("127.0.0.1", 8080, c)
            assert c.attempts == 4
            assert c.other_errors == 1

    def test_do_udp_action_ipv4_and_ipv6(self):
        c = Counters()

        # IPv4 UDP
        with patch("socket.socket") as mock_sock_cls:
            mock_s = MagicMock()
            mock_sock_cls.return_value.__enter__.return_value = mock_s
            do_udp_action("127.0.0.1", 9999, c, size=128)
            assert c.attempts == 1
            assert c.successes == 1

        # IPv6 UDP (detected by colon)
        with patch("socket.socket") as mock_sock_cls:
            mock_s = MagicMock()
            mock_sock_cls.return_value.__enter__.return_value = mock_s
            do_udp_action("::1", 9999, c, size=128)
            assert c.attempts == 2
            assert c.successes == 2

        # UDP OSError
        with patch("socket.socket", side_effect=OSError("Buffer full")):
            do_udp_action("127.0.0.1", 9999, c)
            assert c.attempts == 3
            assert c.other_errors == 1

    def test_rate_dispatched_runner_and_cancellation(self):
        c = Counters()
        stop_event = threading.Event()

        # Test runner executes tasks and halts when stop_event is set
        executed = []
        def task():
            executed.append(1)
            if len(executed) >= 5:
                stop_event.set()

        rate_dispatched_runner(task, duration=2.0, rate=50, c=c, stop=stop_event, max_workers=4)
        assert len(executed) >= 5
        assert stop_event.is_set()

    def test_internet_and_local_or_lan_dispatchers(self):
        c = Counters()
        stop = threading.Event()
        stop.set()  # Stop immediately so loops don't hang

        # Internet dispatcher invocation
        internet(duration=0.1, rate=10, c=c, stop=stop)

        # TCP local mode invocation
        local_or_lan("tcp", "127.0.0.1", 8080, duration=0.1, rate=10, c=c, stop=stop)

        # UDP local mode invocation
        local_or_lan("udp", "127.0.0.1", 9999, duration=0.1, rate=10, c=c, stop=stop)

    def test_stats_loop_output_rendering(self):
        c = Counters()
        c.attempt(100)
        c.success(200)
        stop = threading.Event()

        # Let loop run for one tick then signal stop
        t = threading.Thread(target=stats_loop, args=(c, stop, 10.0))
        t.start()
        time.sleep(0.05)
        stop.set()
        t.join(timeout=2.0)

    def test_validation_all_error_paths(self):
        class MockArgs:
            def __init__(self, mode="internet", target="127.0.0.1", port=80, rate=10, duration=5):
                self.mode = mode
                self.target = target
                self.port = port
                self.rate = rate
                self.duration = duration

        # Duration <= 0
        with pytest.raises(ValueError, match="duration must be"):
            validate(MockArgs(duration=0))

        # Duration > MAX_DURATION
        with pytest.raises(ValueError, match="duration must be"):
            validate(MockArgs(duration=MAX_DURATION + 1))

        # Rate <= 0
        with pytest.raises(ValueError, match="rate must be"):
            validate(MockArgs(rate=0))

        # Internet mode exceeding MAX_INTERNET_RATE
        with pytest.raises(ValueError, match="internet mode is capped"):
            validate(MockArgs(mode="internet", rate=MAX_INTERNET_RATE + 1))

        # Local mode on non-loopback IP
        with pytest.raises(ValueError, match="local mode requires"):
            validate(MockArgs(mode="local", target="192.168.1.10"))

        # TCP/UDP mode on public IP
        with pytest.raises(ValueError, match="high-rate TCP/UDP targets must be private"):
            validate(MockArgs(mode="tcp", target="8.8.8.8"))

        # Rate exceeding MAX_LOCAL_RATE
        with pytest.raises(ValueError, match="local mode is capped"):
            validate(MockArgs(mode="local", target="127.0.0.1", rate=MAX_LOCAL_RATE + 1))

        # Rate exceeding MAX_LAN_RATE
        with pytest.raises(ValueError, match="tcp mode is capped"):
            validate(MockArgs(mode="tcp", target="192.168.1.50", rate=MAX_LAN_RATE + 1))

        # Port out of bounds (< 1 or > 65535)
        with pytest.raises(ValueError, match="port must be"):
            validate(MockArgs(port=0))

        with pytest.raises(ValueError, match="port must be"):
            validate(MockArgs(port=70000))
