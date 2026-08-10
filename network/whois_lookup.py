import time
import ipaddress
import threading
from typing import Dict, Any, Optional
try:
    from ipwhois import IPWhois
except ImportError:
    pass

from storage.models import WhoisInfo

class WhoisLookup:
    """IP Whois Enrichment with caching."""

    def __init__(self, max_cache_size: int = 5000):
        self._cache: Dict[str, dict] = {}
        self._cache_lock = threading.Lock()
        self.ttl = 3600  # seconds
        self.max_cache_size = max_cache_size

    def is_private(self, ip: str) -> bool:
        """Check if RFC1918 private IP."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved
        except ValueError:
            return True # Treat invalid as private to skip

    def lookup(self, ip: str) -> WhoisInfo:
        """Perform Whois lookup."""
        if self.is_private(ip):
            return WhoisInfo(ip=ip)
            
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap()
            net = res.get("network", {}) or {}
            return WhoisInfo(
                ip=ip,
                asn=str(res.get("asn", "")),
                asn_description=str(res.get("asn_description", "")),
                country=str(res.get("asn_country_code", "")),
                network_name=str(net.get("name", "")),
                network_cidr=str(res.get("asn_cidr", "")),
                org=str(net.get("name", "")),
                lookup_time=time.strftime("%Y-%m-%d %H:%M:%S"),
            )
        except Exception:
            return WhoisInfo(ip=ip)

    def lookup_cached(self, ip: str) -> WhoisInfo:
        """Perform Whois lookup with TTL cache."""
        now = time.time()
        with self._cache_lock:
            if ip in self._cache:
                entry = self._cache[ip]
                if now - entry['time'] < self.ttl:
                    return entry['data']

        # Not in cache or expired
        result = self.lookup(ip)
        
        with self._cache_lock:
            if len(self._cache) >= self.max_cache_size:
                expired = [k for k, v in self._cache.items() if now - v['time'] >= self.ttl]
                for k in expired:
                    del self._cache[k]
                if len(self._cache) >= self.max_cache_size:
                    keys = list(self._cache.keys())
                    for k in keys[: len(keys) // 4]:
                        del self._cache[k]
            self._cache[ip] = {
                'time': now,
                'data': result
            }
            
        return result

    def clear_cache(self):
        """Clear the whois cache."""
        with self._cache_lock:
            self._cache.clear()
