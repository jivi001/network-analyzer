# 🛡️ my-sentinel

**A high-performance, real-time CLI & TUI network traffic analyzer, security detection engine, and Nmap network scanner built with Python.**

`my-sentinel` combines live packet capture, continuous multi-vector threat detection, 12 bounded Nmap scan profiles, offline PCAP forensics, and persistent SQLite auditing into a single unified terminal tool.

---

## 🏗️ System Architecture Overview

```text
                               ┌───────────────────────────────────┐
                               │       Network Interface (NIC)     │
                               └─────────────────┬─────────────────┘
                                                 │ Raw Ethernet Packets
                                                 ▼
                               ┌───────────────────────────────────┐
                               │  Scapy Sniffer (core/sniffer.py)  │
                               └─────────────────┬─────────────────┘
                                                 │ Thread-Safe Callback
                                                 ▼
                               ┌───────────────────────────────────┐
                               │ Bounded Queue (queue.Queue 5000)  │
                               └─────────────────┬─────────────────┘
                                                 │ Packet Worker Loop
                                                 ▼
                               ┌───────────────────────────────────┐
                               │ Packet Processor (core/processor) │
                               └─────────┬───────────────┬─────────┘
                                         │               │ Decoded PacketInfo
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
                       │ Central TUI Controller & Shared Console       │
                       │ (tui/dashboard.py & utils/console.py)          │
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
- Single shared Rich console renderer (`utils.console.console`) with no UI overlap.
- BPF capture filtering (`filter="tcp port 80 or tcp port 443"`) with runtime syntax compilation.
- Real-time Exponential Moving Average throughput rates (packets/sec, bytes/sec).
- Memory-bounded processing (5,000 queue limit, 500 packet display ring-buffer).
- Dynamic hotkeys: `[P]ause  [F]ilter  [E]xport  [Q]uit`.

### 🔍 Mode 2: Network Scanner (12 Bounded Profiles)
- `python-nmap` integration with target validation (IPv4, IPv6, CIDR, hostname) and strict allowlist enforcement:
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
- Parses `.pcap` and `.pcapng` files offline via `scapy.PcapReader`.
- Applies the full threat detection pipeline retroactively to historical captures.
- Renders protocol breakdowns, top talkers, and threat alerts tables.

### 📊 Mode 4: Audit & History Management
- Persistent SQLite storage (`sentinel_data.db`) operating in **WAL mode** with `busy_timeout=10000ms`.
- Tracks sessions, alerts, hosts, and scan results with transactional integrity.

### 🛡️ Multi-Vector Threat Detection Engine
- **Signature Engine (`RuleEngine`)**: Evaluates YAML rules (`rules/default_rules.yaml`) with sliding 60s alert deduplication.
- **Behavioral Anomaly Engine (`AnomalyDetector`)**:
  - Shannon Entropy DNS Exfiltration Analysis ($H(X) \ge 3.5$ bits/char).
  - Sliding 10-second window port scan detection ($\ge 15$ target ports).
- **Layer 2 Security (`ArpMonitor`)**: State-machine tracking IP-to-MAC bindings to detect ARP spoofing / MAC mismatches.

---

## 🛠️ Requirements & Setup

- **Python**: 3.10, 3.11, 3.12, 3.13
- **Packet Capture Driver**: Npcap (Windows) in WinPcap API-compatible mode or libpcap (Linux)
- **Scanner**: Nmap 7.90+ in system `%PATH%`
- **Privileges**: Administrator (Windows) or root (Linux)

### Automated Global Setup (Windows)

```powershell
cd D:\Programs\Security\network-analyzer
.\install.ps1
```

Once installed, launch `sentinel` from any terminal prompt:

```powershell
sentinel
```

---

## 📖 Operational Documentation Library (`docs/`)

Explore the operational knowledge base:

| Document | Description |
|----------|-------------|
| [Architecture Guide](file:///d:/Programs/Security/network-analyzer/docs/architecture.md) | Component responsibilities, threading model, and failure degradation. |
| [Installation Guide](file:///d:/Programs/Security/network-analyzer/docs/installation.md) | Requirements, automated setup, and manual virtual environment configuration. |
| [Configuration Reference](file:///d:/Programs/Security/network-analyzer/docs/configuration.md) | Complete `config.yaml` parameter specification and runtime effects. |
| [Quickstart Guide](file:///d:/Programs/Security/network-analyzer/docs/quickstart.md) | 3-minute quickstart guide from zero to live packet capture. |
| [CLI Reference](file:///d:/Programs/Security/network-analyzer/docs/cli-reference.md) | Command-line arguments (`--capture`, `--scan`, `--profile`, `--pcap`, `--mask`). |
| [TUI User Guide](file:///d:/Programs/Security/network-analyzer/docs/tui-guide.md) | Dashboard layout, hotkey controls, and metric calculation formulas. |
| [Packet Capture Engine](file:///d:/Programs/Security/network-analyzer/docs/packet-capture.md) | `PacketSniffer` state machine, background daemon thread, and BPF validation. |
| [Packet Decoding & Pipeline](file:///d:/Programs/Security/network-analyzer/docs/packet-processing.md) | Layer parsing (`Ether`, `IP`, `ARP`, `TCP`, `UDP`, `DNS`, `ICMP`) and null-safety. |
| [Threat Detection Engine](file:///d:/Programs/Security/network-analyzer/docs/detection.md) | YAML rules, Shannon entropy DNS analysis, port scan detection, and ARP monitor. |
| [Network Scanning Engine](file:///d:/Programs/Security/network-analyzer/docs/network-scanning.md) | 12 Nmap scan profiles, target validation, timeout enforcement, and host models. |
| [Offline PCAP Analysis](file:///d:/Programs/Security/network-analyzer/docs/pcap-analysis.md) | Offline PCAP reader pipeline, protocol distributions, and forensic logging. |
| [SQLite Database Layer](file:///d:/Programs/Security/network-analyzer/docs/database.md) | SQLite DDL schema, WAL mode, indexes, and parameterized query methods. |
| [Data Exporter & Importer](file:///d:/Programs/Security/network-analyzer/docs/exports-imports.md) | CSV, JSON, and PCAP export streams, path traversal protection, JSON importer. |
| [Network Intelligence](file:///d:/Programs/Security/network-analyzer/docs/network-intelligence.md) | Reverse DNS resolver, WHOIS lookup engine with TTL caching, ICMP traceroute. |
| [Troubleshooting Guide](file:///d:/Programs/Security/network-analyzer/docs/troubleshooting.md) | Solutions for sniffer permissions, Nmap PATH, SQLite locks, and TUI display. |
| [Developer Debugging](file:///d:/Programs/Security/network-analyzer/docs/debugging.md) | Debug logging, Scapy dissector debugging, thread inspection, and SQLite queries. |
| [Automated Testing](file:///d:/Programs/Security/network-analyzer/docs/testing.md) | Pytest suite breakdown (29 unit & subsystem stress tests). |
| [Performance Architecture](file:///d:/Programs/Security/network-analyzer/docs/performance.md) | Memory bounds, queue limits, EMA rate smoothing, and SQLite WAL pragmas. |
| [Security Controls](file:///d:/Programs/Security/network-analyzer/docs/security.md) | Command injection prevention, BPF checks, path traversal guards, SQL parameters. |
| [Developer Guide](file:///d:/Programs/Security/network-analyzer/docs/development.md) | Repository directory structure, coding standards, and architectural guidelines. |
| [Extension Guide](file:///d:/Programs/Security/network-analyzer/docs/extension-guide.md) | Step-by-step instructions for adding detection rules, scan profiles, and tables. |
| [Data Flow Architecture](file:///d:/Programs/Security/network-analyzer/docs/data-flow.md) | Tracing packet, alert, and scan data flowing through subsystems. |
| [Lifecycle Documentation](file:///d:/Programs/Security/network-analyzer/docs/lifecycle.md) | Application startup lifecycle and 9-step deterministic shutdown sequence. |
| [Functionality Map](file:///d:/Programs/Security/network-analyzer/docs/function-map.md) | Mapping user features to entry points, source files, and functions. |
| [Error Handling Matrix](file:///d:/Programs/Security/network-analyzer/docs/error-handling.md) | Exception origins, user error messages, and system recovery behavior. |
| [FAQ](file:///d:/Programs/Security/network-analyzer/docs/faq.md) | Frequently asked questions on installation, capture, RAM bounds, and Nmap. |

---

## 🧪 Testing Verification

Run the 29-test automated regression and subsystem stress suite:

```powershell
.venv\Scripts\python.exe -m pytest tests\ -v
```

```text
============================= 29 passed in 1.31s ==============================
```
