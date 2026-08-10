# Network Intelligence & Lookups (`network/`)

## 1. Subsystem Overview

The `network/` package provides external lookup capabilities for IP addresses and network nodes:
- **`network/resolver.py`**: Thread-safe reverse DNS resolution with memory caching.
- **`network/whois_lookup.py`**: Autonomous System Number (ASN) and IP ownership lookups via `ipwhois`.
- **`network/traceroute.py`**: Active ICMP/UDP route discovery.

---

## 2. Reverse DNS Resolver (`network/resolver.py`)

`ReverseResolver` resolves IP addresses to domain hostnames using standard socket calls (`socket.gethostbyaddr`):
- Thread-safe dictionary cache (`self._cache`) avoids duplicate DNS queries.
- Negative cache handling: Failed resolutions store the original IP string to prevent repeated timeout delays.
- Configurable timeout per lookup (default: `1.0s`).

---

## 3. Whois Lookup (`network/whois_lookup.py`)

`WhoisLookup` queries WHOIS registrars using the `ipwhois` library:
- Extracts ASN, Org Name, Network CIDR, Country code, and Registrar.
- Enforces TTL-based caching (`whois_cache_ttl`, default: 3600s).
- Gracefully handles private/bogon IP addresses (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.0/8`) without attempting external queries.

---

## 4. Active Traceroute (`network/traceroute.py`)

`Traceroute` executes hop-by-hop ICMP probe packets (TTL 1 to 30) using Scapy:
- Measures per-hop round-trip time (RTT) latency.
- Identifies intermediate router IP addresses and hostnames.
