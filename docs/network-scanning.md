# Network Scanning Engine (`core/scanner.py`)

## 1. Subsystem Overview

`core/scanner.py` integrates Nmap scanning through `python-nmap`. It provides 12 pre-defined, bounded scan profiles with strict target validation, allowlist enforcement, timeout constraints, and standardized `ScanResult` / `HostInfo` model outputs.

---

## 2. Integrated Scan Profiles

| Profile Name | Nmap Arguments | Purpose / Expected Behavior | Privilege Req. |
|--------------|----------------|-----------------------------|----------------|
| **`discovery`** | `-sn` | Ping sweep - discover live hosts without port scanning. | No |
| **`fast_discovery`** | `-sn -T4` | Accelerated ping sweep host discovery. | No |
| **`top_ports`** | `-sS --top-ports 1000` | SYN scan top 1000 TCP ports. | Yes |
| **`service`** | `-sS -sV --top-ports 1000` | SYN scan with service version identification. | Yes |
| **`version`** | `-sV --top-ports 1000` | Probe open ports for service version details. | No |
| **`os_detection`** | `-sS -O --top-ports 1000` | TCP/IP stack fingerprinting for OS identification. | Yes |
| **`comprehensive`** | `-sS -sV -O --top-ports 1000` | Combined SYN, service version, and OS detection. | Yes |
| **`udp_top`** | `-sU --top-ports 100` | Bounded UDP scan top 100 ports. Displays UI latency warning. | Yes |
| **`tcp_connect`** | `-sT --top-ports 1000` | Full unprivileged TCP connect scan. | No |
| **`aggressive`** | `-A --top-ports 1000` | Advanced scan (OS, version, script, traceroute). Displays UI warning. | Yes |
| **`ipv6_discovery`** | `-6 -sn` | Ping sweep over IPv6 targets. | No |
| **`stealth`** | `-sS -T2 --top-ports 100` | Slow, evasive SYN scan top 100 ports. | Yes |

*Note: Backward-compatibility aliases `quick`, `port`, and `full` map to `discovery`, `top_ports`, and `comprehensive` respectively.*

---

## 3. Target Input Validation (`validate_target`)

All target inputs are validated using `validate_target(target)` prior to Nmap execution:
- **IPv4 Address**: `192.168.1.1` validated via `ipaddress.ip_address()`.
- **IPv4 Subnet (CIDR)**: `192.168.1.0/24` validated via `ipaddress.ip_network(strict=False)`.
- **IPv6 Address / Subnet**: `::1` or `2001:db8::/32` validated via `ipaddress`.
- **Hostname**: Alphanumeric strings with dots/hyphens (e.g. `example.com`), rejecting leading hyphens or special shell characters.

Arbitrary command construction via `os.system()` or `subprocess(shell=True)` is **strictly prohibited**.

---

## 4. Timeout Enforcement (`_get_scan_args`)

Every scan profile automatically appends `--host-timeout {timeout}s` based on `config.yaml` (`scanner.timeout`, default: 300s).

---

## 5. Result Parsing & Normalization (`_parse_results`)

Nmap results are parsed into standardized `HostInfo` dataclass objects:
- **IP & MAC Address**: Extracted from Nmap address dictionaries.
- **Hostname & State**: Extracted via `nm[host].hostname()` and `nm[host].state()`.
- **OS Guess**: Extracted from `osmatch[0]["name"]`.
- **Open Ports & Service Details**: Extracts state (`open` / `open|filtered`), service name, product, version, and extra info. Formats detailed string `f"{service_name} ({product} {version})"`.
