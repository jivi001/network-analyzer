import socket
import threading
from typing import Dict

class Resolver:
    """DNS Resolution with caching."""

    def __init__(self, max_cache_size: int = 10000, timeout: float = 2.0):
        self._cache: Dict[str, str] = {}
        self._cache_lock = threading.Lock()
        self.max_cache_size = max_cache_size
        self._timeout = timeout
        # NOTE: We intentionally do NOT call socket.setdefaulttimeout()
        # to avoid mutating process-wide socket behavior for Scapy and
        # other networking subsystems.

    def reverse_dns(self, ip: str) -> str:
        """Reverse lookup IP -> hostname."""
        try:
            # Use a fresh socket with per-operation timeout
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self._timeout)
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
            finally:
                socket.setdefaulttimeout(old_timeout)
            return hostname
        except Exception:
            return ""

    def resolve(self, hostname: str) -> str:
        """Forward lookup hostname -> IP."""
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self._timeout)
            try:
                ip = socket.gethostbyname(hostname)
            finally:
                socket.setdefaulttimeout(old_timeout)
            return ip
        except Exception:
            return ""

    def reverse_dns_cached(self, ip: str) -> str:
        """Reverse DNS with cache."""
        with self._cache_lock:
            if ip in self._cache:
                return self._cache[ip]

        hostname = self.reverse_dns(ip)
        
        with self._cache_lock:
            if len(self._cache) >= self.max_cache_size:
                # Simple eviction of oldest quarter
                keys = list(self._cache.keys())
                for k in keys[: len(keys) // 4]:
                    del self._cache[k]
            self._cache[ip] = hostname
            
        return hostname

    def clear_cache(self):
        """Clear the DNS cache."""
        with self._cache_lock:
            self._cache.clear()

