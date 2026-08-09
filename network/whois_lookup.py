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

    def __init__(self):
        self._cache: Dict[str, dict] = {}
        self._cache_lock = threading.Lock()
        self.ttl = 3600  # seconds

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
            return WhoisInfo(asn="", asn_cidr="", asn_country_code="", asn_date="", asn_registry="", asn_description="", network={})
            
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap()
            return WhoisInfo(
                asn=res.get("asn", ""),
                asn_cidr=res.get("asn_cidr", ""),
                asn_country_code=res.get("asn_country_code", ""),
                asn_date=res.get("asn_date", ""),
                asn_registry=res.get("asn_registry", ""),
                asn_description=res.get("asn_description", ""),
                network=res.get("network", {})
            )
        except Exception:
            return WhoisInfo(asn="", asn_cidr="", asn_country_code="", asn_date="", asn_registry="", asn_description="", network={})

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
            self._cache[ip] = {
                'time': now,
                'data': result
            }
            
        return result

    def clear_cache(self):
        """Clear the whois cache."""
        with self._cache_lock:
            self._cache.clear()
