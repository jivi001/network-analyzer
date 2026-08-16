"""
test_unit_traffic_lab.py — Comprehensive unit tests for traffic generator and rate control.
"""

import socket
import time
from unittest.mock import patch, MagicMock
import pytest

from traffic_lab import (
    Counters,
    dns_query,
    http_get,
    do_internet_action,
    validate,
    MAX_INTERNET_RATE,
    MAX_LAN_RATE,
    MAX_LOCAL_RATE,
)


class TestTrafficLabCounters:
    def test_counters_accounting(self):
        c = Counters()
        assert c.attempts == 0
        assert c.successes == 0
        assert c.failures == 0

        c.attempt(tx=64)
        c.success(rx=128)
        assert c.attempts == 1
        assert c.successes == 1
        assert c.tx == 64
        assert c.rx == 128

        c.attempt(tx=64)
        c.failure("timeout")
        assert c.attempts == 2
        assert c.failures == 1
        assert c.timeouts == 1

        c.attempt(tx=64)
        c.failure("refused")
        assert c.attempts == 3
        assert c.failures == 2
        assert c.refused == 1

        c.attempt(tx=64)
        c.failure("error")
        assert c.attempts == 4
        assert c.failures == 3
        assert c.other_errors == 1


class TestTrafficLabValidation:
    def test_validate_args(self):
        class MockArgs:
            def __init__(self, mode, target, rate, duration, port=80):
                self.mode = mode
                self.target = target or "127.0.0.1"
                self.rate = rate
                self.duration = duration
                self.port = port

        # Internet mode valid
        args_valid = MockArgs("internet", None, 10, 5)
        validate(args_valid)

        # Internet mode exceeding rate limit
        args_high_rate = MockArgs("internet", None, 100, 5)
        with pytest.raises(ValueError):
            validate(args_high_rate)

        # Local mode on private IP valid
        args_local = MockArgs("tcp", "127.0.0.1", 50, 5, port=80)
        validate(args_local)

        # Local mode on public IP invalid
        args_public_tcp = MockArgs("tcp", "8.8.8.8", 50, 5, port=80)
        with pytest.raises(ValueError):
            validate(args_public_tcp)


class TestTrafficLabInternetActions:
    def test_do_internet_action_mocked_success(self):
        c = Counters()
        with patch("traffic_lab.http_get", return_value=512), \
             patch("traffic_lab.dns_query", return_value=64):
            do_internet_action(c)
            assert c.attempts == 1
            assert c.successes == 1

    def test_do_internet_action_timeout_handling(self):
        c = Counters()
        with patch("traffic_lab.http_get", side_effect=socket.timeout):
            with patch("random.random", return_value=0.1):  # Force HTTP
                do_internet_action(c)
                assert c.attempts == 1
                assert c.failures == 1
                assert c.timeouts == 1
