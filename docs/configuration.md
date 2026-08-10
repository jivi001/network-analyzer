# Configuration Reference (`config.yaml`)

## 1. Overview

`my-sentinel` reads runtime options from `config.yaml` located in the root directory. If `config.yaml` is absent, hardcoded fallback defaults in code are applied. Custom configuration paths can be specified at runtime using the `--config <path>` CLI option.

---

## 2. Complete Configuration Reference

```yaml
# my-sentinel configuration

general:
  app_name: "my-sentinel"
  version: "1.0.0"
  database_path: "sentinel_data.db"

capture:
  interface: ""                  # Network interface (blank = auto-detect via scapy.conf.iface)
  packet_buffer_size: 500        # In-memory packet ring-buffer for TUI display
  refresh_fps: 4                 # Dashboard refresh rate (frames per second)
  default_filter: ""             # Default BPF capture filter
  privacy_mask: false            # Enable IP privacy masking by default

scanner:
  timeout: 300                   # Scan timeout in seconds (--host-timeout)
  discovery: "-sn"               # Arguments for discovery profile
  fast_discovery: "-sn -T4"      # Arguments for fast_discovery profile
  top_ports: "-sS --top-ports 1000"
  service: "-sS -sV --top-ports 1000"
  version: "-sV --top-ports 1000"
  os_detection: "-sS -O --top-ports 1000"
  comprehensive: "-sS -sV -O --top-ports 1000"
  udp_top: "-sU --top-ports 100"
  tcp_connect: "-sT --top-ports 1000"
  aggressive: "-A --top-ports 1000"
  ipv6_discovery: "-6 -sn"
  stealth: "-sS -T2 --top-ports 100"

detection:
  rules_directory: "rules"       # Path to YAML detection rules directory
  dedup_window: 60               # Alert deduplication window in seconds
  max_alerts: 100                # Maximum alerts kept in memory buffer
  dns_entropy_threshold: 3.5     # Shannon entropy threshold for DNS exfiltration
  dns_min_subdomain_length: 20   # Minimum domain length before entropy check
  beacon_interval_tolerance: 5.0 # Beaconing tolerance in seconds

network:
  enable_whois: true             # Enable IP Whois lookups
  whois_cache_ttl: 3600          # Whois cache time-to-live (seconds)
  enable_rdns: true              # Enable reverse DNS resolution
  enable_traceroute: false       # Enable active ICMP traceroute

export:
  export_directory: "exports"   # Target directory for exported files
  json_include_payload: false    # Include raw payload in JSON exports
```

---

## 3. Key Parameters & Runtime Impact

| Section | Parameter | Type | Default | Runtime Effect |
|---------|-----------|------|---------|----------------|
| `general` | `database_path` | str | `"sentinel_data.db"` | SQLite database file location. |
| `capture` | `interface` | str | `""` | Binds sniffer to specified NIC string (e.g. `"Ethernet"`). |
| `capture` | `packet_buffer_size` | int | `500` | Limits live packet table ring buffer length in RAM. |
| `scanner` | `timeout` | int | `300` | Enforces `--host-timeout {timeout}s` on all Nmap scans. |
| `detection` | `dns_entropy_threshold` | float | `3.5` | Flags DNS queries whose subdomain Shannon entropy exceeds 3.5 bits/char. |
| `detection` | `dedup_window` | int | `60` | Suppresses duplicate rule alerts from same `(rule, src_ip, dst_ip)` within 60s. |
| `export` | `export_directory` | str | `"exports"` | Destination folder created for CSV/JSON/PCAP exports. |
