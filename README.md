# 🛡️ my-sentinel

**A high-performance, real-time CLI & TUI network traffic analyzer, security detection engine, and Nmap network scanner built with Python.**

`my-sentinel` combines live packet capture, continuous multi-vector threat detection, 12 bounded Nmap scan profiles, offline PCAP forensics, format-specific export capabilities, and persistent SQLite auditing into a single unified terminal tool.

---

## 🏗️ System Architecture Overview

```text
                               ┌───────────────────────────────────┐
                               │       Network Interface (NIC)     │
                               └─────────────────┬─────────────────┘
                                                 │ Raw Ethernet / IP Packets
                                                 ▼
                               ┌───────────────────────────────────┐
                               │  Scapy Sniffer (core/sniffer.py)  │
                               └─────────────────┬─────────────────┘
                                                 │ Thread-Safe Callback
                                                 ▼
                               ┌───────────────────────────────────┐
                               │ Bounded Queue (queue.Queue 10000) │
                               └─────────────────┬─────────────────┘
                                                 │ Packet Worker Loop
                                                 ▼
                               ┌───────────────────────────────────┐
                               │ Packet Processor (core/processor) │
                               └─────────┬───────────────┬─────────┘
                                         │               │ Decoded PacketInfo (IPv4/IPv6/ARP/DNS/TCP/UDP/ICMP)
                                         ▼               ▼
                       ┌───────────────────┐   ┌───────────────────────────────┐
                       │  StatsAggregator  │   │ Detection Pipeline (pipeline) │
                       │   (core/stats.py) │   ├───────────────────────────────┤
                       └─────────┬─────────┘   │ • RuleEngine (rules/yaml)     │
                                 │             │ • AnomalyDetector (entropy/scan)
                                 │             │ • ArpMonitor (mac binding)    │
                                 │             └───────────────┬───────────────┘
                                 │                             │ AlertInfo
                                 ▼                             ▼
                       ┌───────────────────────────────────────────────┐
                       │  AlertManager (detection/alerts.py)           │
                       └─────────────────┬─────────────────────────────┘
                                         │
                                         ▼
                       ┌───────────────────────────────────────────────┐
                       │ Central TUI Controller & Screen Lifecycle     │
                       │ (tui/dashboard.py & utils/console.py)         │
                       └─────────────────┬─────────────────────────────┘
                                         │
                                         ▼
                       ┌───────────────────────────────────────────────┐
                       │ SQLite Database (storage/database.py)         │
                       └───────────────────────────────────────────────┘
```

---

## ✨ Core Capabilities

### 🔴 Mode 1: Live Packet Capture & Streaming
- Non-blocking packet sniffing using Scapy in a background thread (`PacketSniffer`).
- Single shared Rich console renderer (`utils.console.console`) with strict `ScreenState` screen lifecycle ownership.
- BPF capture filtering (`filter="tcp port 80 or tcp port 443"`) with runtime syntax compilation and validation.
- Real-time Exponential Moving Average throughput rates (capture PPS vs processing PPS) and sustained backlog detection.
- Sampled background system telemetry (process CPU %, resident RAM in MB, active thread count).
- Memory-bounded processing (10,000 queue limit, bounded packet display ring-buffer).
- Dynamic hotkeys: `[P]ause  [F]ilter  [E]xport  [Q]uit`.

### 🔍 Mode 2: Network Scanner (12 Bounded Profiles)
- `python-nmap` integration with target validation (IPv4, IPv6, CIDR, hostname) and strict argument allowlist enforcement:
  1. `discovery`: Live host discovery sweep (`-sn`)
  2. `fast_discovery`: Accelerated ping sweep (`-sn -T4`)
  3. `top_ports`: TCP SYN scan top 1000 ports (`-sS --top-ports 1000`)
  4. `service`: Service version identification (`-sS -sV --top-ports 1000`)
  5. `version`: Service version enumeration (`-sV --top-ports 1000`)
  6. `os_detection`: OS stack fingerprinting (`-sS -O --top-ports 1000`)
  7. `comprehensive`: SYN, version, and OS detection (`-sS -sV -O --top-ports 1000`)
  8. `udp_top`: UDP scan top 100 ports (`-sU --top-ports 100`)
  9. `tcp_connect`: Unprivileged TCP connect scan (`-sT --top-ports 1000`)
  10. `aggressive`: OS, version, script, traceroute (`-A --top-ports 1000`)
  11. `ipv6_discovery`: IPv6 host discovery sweep (`-6 -sn`)
  12. `stealth`: Evasive slow SYN scan (`-sS -T2 --top-ports 100`)

### 📂 Mode 3: Offline PCAP Forensic Analysis
- Parses `.pcap`, `.pcapng`, and `.cap` files offline via streaming `scapy.PcapReader` in constant memory.
- Decodes IPv4, IPv6, ARP, TCP, UDP, DNS, ICMP, and non-Ethernet link layers.
- Calculates truthful forensic capture duration and packet rates from packet timestamps.
- Aggregates protocol distribution, top data sources, top network conversations, and flags historical security threats.
- Interactive path resolution with numbered quick-select for existing captures, quote stripping, and fuzzy "Did you mean?" suggestion for typos.

### 💾 Format-Specific Export Subsystem
- **`.pcap`**: Exports raw Scapy packet binaries verifiable by Wireshark and tcpdump.
- **`.csv`**: Formats structured RFC 4180 CSV with escaped delimiters for packet event logs and security alert feeds.
- **`.json`**: Serializes machine-readable structured JSON with application metadata, capture stats, alerts, hosts, and packet streams.
- Path traversal guards protecting against unauthorized directory writes.

### 📊 Mode 4: Audit & History Management
- Persistent SQLite storage (`sentinel_data.db`) operating in **WAL mode** with `busy_timeout=5000ms`.
- Tracks sessions, alerts, hosts, packet summaries, and scan results with transactional integrity.

### 🛡️ Multi-Vector Threat Detection Engine
- **Signature Engine (`RuleEngine`)**: Evaluates YAML rules (`rules/default_rules.yaml`) with sliding 60s alert deduplication.
- **Behavioral Anomaly Engine (`AnomalyDetector`)**:
  - Shannon Entropy DNS Exfiltration Analysis ($H(X) \ge 3.5$ bits/char with subsegment correlation).
  - Sliding 10-second window port scan detection ($\ge 15$ target ports).
- **Layer 2 Security (`ArpMonitor`)**: State-machine tracking IP-to-MAC bindings to detect ARP spoofing / MAC mismatches.

### 🧪 Controlled Real Traffic Lab (`traffic_lab.py`)
- High-precision token/interval rate dispatcher for benchmark testing.
- Bounded thread worker pool preventing network latency from bottlenecking target generation rate.
- Fine-grained diagnostic breakdown tracking attempts, successes, timeouts, and connection errors.

---

## 🛠️ Requirements & Setup

- **Python**: 3.10, 3.11, 3.12, 3.13
- **Packet Capture Driver**: Npcap (Windows) in WinPcap API-compatible mode or libpcap (Linux)
- **Scanner**: Nmap 7.90+ in system `%PATH%`
- **Privileges**: Administrator (Windows) or root (Linux) for raw SYN scans / sniffing

### Quick Setup

#### Windows (PowerShell)

```powershell
cd network-analyzer
.\install.ps1
```

Once installed, launch `sentinel` from any terminal prompt:

```powershell
sentinel
```

#### Linux / macOS (Bash)

```bash
cd network-analyzer
chmod +x install.sh
./install.sh
sentinel
```

---

## 📖 Operational Documentation Library (`docs/`)

Explore the operational knowledge base:

| Document | Description |
|----------|-------------|
| [Architecture Guide](docs/architecture.md) | Component responsibilities, threading model, and failure degradation. |
| [Installation Guide](docs/installation.md) | Requirements, automated setup, and manual virtual environment configuration. |
| [Configuration Reference](docs/configuration.md) | Complete `config.yaml` parameter specification and runtime effects. |
| [Quickstart Guide](docs/quickstart.md) | 3-minute quickstart guide from zero to live packet capture. |
| [CLI Reference](docs/cli-reference.md) | Command-line arguments (`--capture`, `--scan`, `--profile`, `--pcap`, `--mask`). |
| [TUI User Guide](docs/tui-guide.md) | Dashboard layout, hotkey controls, and metric calculation formulas. |
| [Packet Capture Engine](docs/packet-capture.md) | `PacketSniffer` state machine, background daemon thread, and BPF validation. |
| [Packet Decoding & Pipeline](docs/packet-processing.md) | Layer parsing (`Ether`, `IP`, `IPv6`, `ARP`, `TCP`, `UDP`, `DNS`, `ICMP`). |
| [Threat Detection Engine](docs/detection.md) | YAML rules, Shannon entropy DNS analysis, port scan detection, and ARP monitor. |
| [Network Scanning Engine](docs/network-scanning.md) | 12 Nmap scan profiles, target validation, timeout enforcement, and host models. |
| [Offline PCAP Analysis](docs/pcap-analysis.md) | Offline PCAP reader pipeline, forensic duration, path suggestions, and logging. |
| [SQLite Database Layer](docs/database.md) | SQLite DDL schema, WAL mode, indexes, and parameterized query methods. |
| [Data Exporter & Importer](docs/exports-imports.md) | Format-specific CSV, JSON, and binary PCAP export streams with security guards. |
| [Network Intelligence](docs/network-intelligence.md) | Reverse DNS resolver, WHOIS lookup engine with TTL caching, ICMP traceroute. |
| [Troubleshooting Guide](docs/troubleshooting.md) | Solutions for sniffer permissions, Nmap PATH, SQLite locks, and TUI display. |
| [Developer Debugging](docs/debugging.md) | Debug logging, Scapy dissector debugging, thread inspection, and SQLite queries. |
| [Automated Testing](docs/testing.md) | Pytest suite breakdown (167 unit, subsystem stress, and end-to-end workflow tests). |
| [Performance Architecture](docs/performance.md) | Memory bounds, 10,000 queue limits, EMA rate smoothing, and SQLite WAL pragmas. |
| [Security Controls](docs/security.md) | Command injection prevention, BPF checks, path traversal guards, SQL parameters. |
| [Developer Guide](docs/development.md) | Repository directory structure, coding standards, and architectural guidelines. |
| [Extension Guide](docs/extension-guide.md) | Step-by-step instructions for adding detection rules, scan profiles, and tables. |
| [Data Flow Architecture](docs/data-flow.md) | Tracing packet, alert, and scan data flowing through subsystems. |
| [Lifecycle Documentation](docs/lifecycle.md) | Application startup lifecycle and 9-step deterministic shutdown sequence. |
| [Functionality Map](docs/function-map.md) | Mapping user features to entry points, source files, and functions. |
| [Error Handling Matrix](docs/error-handling.md) | Exception origins, user error messages, and system recovery behavior. |
| [FAQ](docs/faq.md) | Frequently asked questions on installation, capture, RAM bounds, and Nmap. |

---

## 🧪 Testing Verification

Run the 244-test automated regression, stress, and end-to-end workflow suite:

```powershell
.venv\Scripts\python.exe -m pytest tests/ -v
```

```text
============================ 244 passed in 19.41s =============================
```
