#!/usr/bin/env python3
"""Controlled real-traffic generator for testing my-sentinel.

Defaults to low-rate public Internet traffic. High-rate TCP/UDP modes are
restricted to loopback/private/link-local targets. Use only on systems and
networks you own or are authorized to test.
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import os
import random
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlparse

MAX_DURATION = 15 * 60
MAX_INTERNET_RATE = 50
MAX_LAN_RATE = 5000
MAX_LOCAL_RATE = 10000
PUBLIC_HTTP = ("https://example.com/", "https://www.cloudflare.com/cdn-cgi/trace")
PUBLIC_DNS = (("1.1.1.1", 53), ("8.8.8.8", 53))


@dataclass
class Counters:
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    timeouts: int = 0
    refused: int = 0
    other_errors: int = 0
    tx: int = 0
    rx: int = 0
    started: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def attempt(self, tx=0):
        with self.lock:
            self.attempts += 1
            self.tx += tx

    def success(self, rx=0):
        with self.lock:
            self.successes += 1
            self.rx += rx

    def failure(self, category: str = "error"):
        with self.lock:
            self.failures += 1
            if category == "timeout":
                self.timeouts += 1
            elif category == "refused":
                self.refused += 1
            else:
                self.other_errors += 1


def dns_query(server, hostname="www.example.com") -> int:
    tid = random.randrange(65536)
    qname = b"".join(bytes([len(x)]) + x.encode() for x in hostname.split(".")) + b"\0"
    packet = (tid.to_bytes(2, "big") + b"\x01\x00" + b"\x00\x01" +
              b"\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2.0)
        s.sendto(packet, server)
        data, _ = s.recvfrom(4096)
        return len(data)


def http_get(url) -> int:
    u = urlparse(url)
    if u.scheme != "https":
        raise ValueError("Only HTTPS endpoints are allowed")
    conn = http.client.HTTPSConnection(
        u.hostname,
        u.port or 443,
        timeout=3.0,
        context=ssl.create_default_context(),
    )
    try:
        conn.request("GET", u.path or "/", headers={
            "User-Agent": "my-sentinel-traffic-lab/1.0",
            "Connection": "close",
        })
        r = conn.getresponse()
        remaining = 64 * 1024
        total = 0
        while remaining:
            chunk = r.read(min(8192, remaining))
            if not chunk:
                break
            total += len(chunk)
            remaining -= len(chunk)
        return total
    finally:
        conn.close()


def do_internet_action(c: Counters):
    """Executes a single HTTP or DNS request with truthful attempt accounting."""
    c.attempt(64)
    try:
        if random.random() < 0.65:
            rx = http_get(random.choice(PUBLIC_HTTP))
        else:
            rx = dns_query(random.choice(PUBLIC_DNS))
        c.success(rx)
    except (socket.timeout, TimeoutError):
        c.failure("timeout")
    except ConnectionRefusedError:
        c.failure("refused")
    except Exception:
        c.failure("error")


def do_tcp_action(target: str, port: int, c: Counters):
    """Executes a single TCP connection attempt with precise error categorization."""
    payload = b"my-sentinel-traffic-lab\n"
    c.attempt(len(payload))
    try:
        with socket.create_connection((target, port), timeout=1.0) as s:
            s.sendall(payload)
            c.success(0)
    except (socket.timeout, TimeoutError):
        c.failure("timeout")
    except ConnectionRefusedError:
        c.failure("refused")
    except OSError:
        c.failure("error")


def do_udp_action(target: str, port: int, c: Counters, size: int = 256):
    """Executes a single UDP datagram transmission."""
    payload = os.urandom(size)
    c.attempt(len(payload))
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.sendto(payload, (target, port))
            c.success(0)
    except OSError:
        c.failure("error")


def rate_dispatched_runner(task_fn, duration: float, rate: float, c: Counters, stop: threading.Event, max_workers: int = 32):
    """
    Precision Token/Interval Dispatcher:
    Schedules task execution at the exact configured rate using a bounded worker pool.
    Prevents single-thread network RTT latency from bottlenecking target generation rate.
    """
    interval = 1.0 / rate
    end_time = time.monotonic() + duration
    next_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        while time.monotonic() < end_time and not stop.is_set():
            executor.submit(task_fn)

            next_time += interval
            sleep_time = next_time - time.perf_counter()
            if sleep_time > 0:
                time.sleep(sleep_time)
            elif sleep_time < -0.5:
                # Reset if accumulated drift exceeds 500ms
                next_time = time.perf_counter()


def internet(duration: float, rate: float, c: Counters, stop: threading.Event):
    workers = min(40, max(4, int(rate * 2)))
    rate_dispatched_runner(lambda: do_internet_action(c), duration, rate, c, stop, max_workers=workers)


def local_or_lan(mode: str, target: str, port: int, duration: float, rate: float, c: Counters, stop: threading.Event):
    if mode == "tcp":
        workers = min(100, max(8, int(rate * 0.5))) if rate > 50 else 16
        rate_dispatched_runner(lambda: do_tcp_action(target, port, c), duration, rate, c, stop, max_workers=workers)
    else:
        # UDP does not block on connection handshakes; fast direct dispatch
        interval = 1.0 / rate
        end_time = time.monotonic() + duration
        next_time = time.perf_counter()
        while time.monotonic() < end_time and not stop.is_set():
            do_udp_action(target, port, c)
            next_time += interval
            sleep_time = next_time - time.perf_counter()
            if sleep_time > 0:
                time.sleep(sleep_time)
            elif sleep_time < -0.1:
                next_time = time.perf_counter()


def stats_loop(c: Counters, stop: threading.Event, requested_rate: float):
    while not stop.wait(1.0):
        with c.lock:
            a, ok, fail = c.attempts, c.successes, c.failures
            tout, ref, err = c.timeouts, c.refused, c.other_errors
            tx, rx = c.tx, c.rx
        elapsed = max(time.monotonic() - c.started, 0.001)
        actual_rate = a / elapsed
        print(f"\r[Req: {requested_rate:.0f}/s] Attempts {a:8,d} | OK {ok:8,d} | Fail {fail:7,d} "
              f"(TOut: {tout}, Ref: {ref}) | Rate: {actual_rate:6.1f}/s | TX {tx/1024:7.1f} KiB",
              end="", flush=True)


def validate(args):
    if args.duration <= 0 or args.duration > MAX_DURATION:
        raise ValueError(f"duration must be 0 < duration <= {MAX_DURATION}")
    if args.rate <= 0:
        raise ValueError("rate must be > 0")
    if args.mode == "internet" and args.rate > MAX_INTERNET_RATE:
        raise ValueError(f"internet mode is capped at {MAX_INTERNET_RATE}/s")
    if args.mode in ("tcp", "udp", "local"):
        ip = ipaddress.ip_address(args.target)
        if args.mode == "local" and not ip.is_loopback:
            raise ValueError("local mode requires 127.0.0.1 or ::1")
        if args.mode in ("tcp", "udp") and not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise ValueError("high-rate TCP/UDP targets must be private, loopback, or link-local")
        cap = MAX_LOCAL_RATE if args.mode == "local" else MAX_LAN_RATE
        if args.rate > cap:
            raise ValueError(f"{args.mode} mode is capped at {cap}/s")
    if not 1 <= args.port <= 65535:
        raise ValueError("port must be 1..65535")


def main():
    p = argparse.ArgumentParser(description="Real traffic generator for my-sentinel live-capture testing")
    p.add_argument("--mode", choices=("internet", "tcp", "udp", "local"), default="internet")
    p.add_argument("--duration", type=float, default=60)
    p.add_argument("--rate", type=float, default=10)
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    args = p.parse_args()
    try:
        validate(args)
    except ValueError as e:
        p.error(str(e))

    print("[MY-SENTINEL REAL TRAFFIC LAB]")
    print(f"  Mode:           {args.mode}")
    print(f"  Target Rate:    {args.rate}/s")
    print(f"  Duration:       {args.duration}s")
    if args.mode in ("tcp", "udp", "local"):
        print(f"  Destination:    {args.target}:{args.port}")
    print("Start my-sentinel Live Capture first. Ctrl+C stops this generator.\n")

    c = Counters()
    stop = threading.Event()
    t = threading.Thread(target=stats_loop, args=(c, stop, args.rate), daemon=True)
    t.start()
    try:
        if args.mode == "internet":
            internet(args.duration, args.rate, c, stop)
        elif args.mode == "local":
            local_or_lan("udp", args.target, args.port, args.duration, args.rate, c, stop)
        else:
            local_or_lan(args.mode, args.target, args.port, args.duration, args.rate, c, stop)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        stop.set()
        t.join(2.0)

    with c.lock:
        elapsed = max(time.monotonic() - c.started, 0.001)
        actual_attempt_rate = c.attempts / elapsed
        actual_success_rate = c.successes / elapsed
        print("\n\n=== Final Diagnostic Report ===")
        print(f"  Requested Rate:       {args.rate:.1f}/s")
        print(f"  Actual Attempt Rate:  {actual_attempt_rate:.1f}/s")
        print(f"  Actual Success Rate:  {actual_success_rate:.1f}/s")
        print(f"  Total Attempted:      {c.attempts:,}")
        print(f"  Total Successful:     {c.successes:,}")
        print(f"  Total Failed:         {c.failures:,}")
        print(f"    - Timeouts:         {c.timeouts:,}")
        print(f"    - Refused / Unreach:{c.refused:,}")
        print(f"    - Other Errors:     {c.other_errors:,}")
        print(f"  Volume Transmitted:   {c.tx/1024:.1f} KiB")
        print(f"  Volume Received:      {c.rx/1024:.1f} KiB")


if __name__ == "__main__":
    raise SystemExit(main())
