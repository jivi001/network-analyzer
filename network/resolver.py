import socket
import threading
from typing import Dict

class Resolver:
    """DNS Resolution with caching."""

    def __init__(self):
        self._cache: Dict[str, str] = {}
        self._cache_lock = threading.Lock()
        socket.setdefaulttimeout(2.0)

    def reverse_dns(self, ip: str) -> str:
        """Reverse lookup IP -> hostname."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return ""

    def resolve(self, hostname: str) -> str:
        """Forward lookup hostname -> IP."""
        try:
            ip = socket.gethostbyname(hostname)
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
            self._cache[ip] = hostname
            
        return hostname

    def clear_cache(self):
        """Clear the DNS cache."""
        with self._cache_lock:
            self._cache.clear()
