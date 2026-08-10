# `my-sentinel` Architecture & System Design

## 1. System Overview

`my-sentinel` is a real-time network traffic analyzer, threat detection engine, and security scanner with a Rich terminal user interface (TUI). Built using Python, Scapy, SQLite, and Nmap, `my-sentinel` provides non-intrusive live packet capture, continuous multi-vector anomaly detection, PCAP file forensic analysis, target scanning, and persistent session auditing.

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

## 2. Directory Structure & Subsystem Boundaries

| Directory / File | Subsystem | Key Responsibilities |
|------------------|-----------|----------------------|
| [sentinel.py](file:///d:/Programs/Security/network-analyzer/sentinel.py) | Application Entry & Controller | CLI argument parsing, startup orchestration, interactive menu routing, graceful shutdown sequence. |
| [config.yaml](file:///d:/Programs/Security/network-analyzer/config.yaml) | Configuration System | YAML configuration defaults for capture buffers, scanner timeouts, detection thresholds, and exports. |
| [core/sniffer.py](file:///d:/Programs/Security/network-analyzer/core/sniffer.py) | Live Packet Capture | Scapy wrapper (`PacketSniffer`), daemon sniffing thread, BPF filter application, capture state machine. |
| [core/processor.py](file:///d:/Programs/Security/network-analyzer/core/processor.py) | Packet Decoder | Converts raw Scapy packet objects into standardized `PacketInfo` dataclass instances. |
| [core/scanner.py](file:///d:/Programs/Security/network-analyzer/core/scanner.py) | Network Scanner | Nmap integration via `python-nmap`, 12 bounded scan profiles, allowlist enforcement, target validation. |
| [core/stats.py](file:///d:/Programs/Security/network-analyzer/core/stats.py) | Metric Aggregator | Thread-safe `StatsAggregator`, protocol counts, IP volume tracking, top talkers, exponential moving average rates. |
| [detection/pipeline.py](file:///d:/Programs/Security/network-analyzer/detection/pipeline.py) | Detection Pipeline | `PacketDetectionPipeline` delegating to `RuleEngine`, `AnomalyDetector`, and `ArpMonitor`. |
| [detection/rule_engine.py](file:///d:/Programs/Security/network-analyzer/detection/rule_engine.py) | Signature Engine | Evaluates YAML signature rules against `PacketInfo` attributes with deduplication windows. |
| [detection/anomaly.py](file:///d:/Programs/Security/network-analyzer/detection/anomaly.py) | Behavioral Engine | Shannon entropy DNS exfiltration analysis and sliding-window port scan detection. |
| [detection/arp_monitor.py](file:///d:/Programs/Security/network-analyzer/detection/arp_monitor.py) | L2 Security | IP-to-MAC mapping state machine for ARP spoofing and MAC alteration detection. |
| [detection/alerts.py](file:///d:/Programs/Security/network-analyzer/detection/alerts.py) | Alert Manager | Ring buffer memory storage, severity filtering, alert counters, SQLite persistence. |
| [storage/database.py](file:///d:/Programs/Security/network-analyzer/storage/database.py) | SQLite Storage Layer | Thread-safe connection pooling, WAL mode, Schema DDL, transactional sessions, alerts, hosts, and scan results. |
| [storage/models.py](file:///d:/Programs/Security/network-analyzer/storage/models.py) | Data Models | Dataclasses: `PacketInfo`, `AlertInfo`, `SessionInfo`, `HostInfo`, `ScanResult`, `StatsSnapshot`. |
| [storage/exporter.py](file:///d:/Programs/Security/network-analyzer/storage/exporter.py) | Exporter | CSV, JSON, and PCAP export streams with path traversal protection. |
| [storage/importer.py](file:///d:/Programs/Security/network-analyzer/storage/importer.py) | Importer | Session import and strict JSON file parsing with schema validation. |
| [tui/](file:///d:/Programs/Security/network-analyzer/tui/) | Rich TUI Subsystem | Single `Console` view routing (`dashboard.py`, `menu.py`, `scan_view.py`, `pcap_view.py`, `history_view.py`). |
| [utils/console.py](file:///d:/Programs/Security/network-analyzer/utils/console.py) | Console Renderer | Single shared `Console` instance owner preventing TUI rendering overlap. |
| [utils/privacy.py](file:///d:/Programs/Security/network-analyzer/utils/privacy.py) | Privacy Masking | Deterministic or anonymized IP address masking filter (`PrivacyFilter`). |
| [utils/privileges.py](file:///d:/Programs/Security/network-analyzer/utils/privileges.py) | Environment Checks | Windows Administrator check (`ctypes.windll.shell32.IsUserAnAdmin`), Npcap and Nmap validation. |

---

## 3. Component Interaction & Threading Architecture

```text
               MAIN THREAD (sentinel.py)
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   TUI Live Loop   Sniffer Thread   Worker Threads
   (Render View)   (scapy.sniff)    (Rate Calc)
```

1. **Main Thread**: Owns the CLI/TUI lifecycle loop, user keyboard input handling, database transactions, and view transitions.
2. **Sniffer Background Thread (`PacketSniffer`)**: Spawns a daemon thread executing `scapy.sniff(iface=..., prn=...)`. Places raw packets onto a bounded `queue.Queue`.
3. **Packet Worker Loop (`run_live_capture`)**: Drains the queue in batches, decodes packets via `process_packet`, passes `PacketInfo` to `StatsAggregator`, `PcapWriter`, and `PacketDetectionPipeline`.
4. **Rate Calculator Thread (`StatsAggregator`)**: Runs a 1-second interval daemon thread computing exponential moving averages (`alpha=0.5`) for packets/sec and bytes/sec.

---

## 4. Failure Isolation & Degradation Model

If a subsystem encounters an unhandled exception or resource exhaustion:
- **PCAP Writer Error**: Logged to `logger.error()`, subsystem marked as `DEGRADED`, capture continues without crashing the application.
- **Rule Engine Error**: Exception caught in `PacketDetectionPipeline`, logged, and remaining pipeline stages continue processing.
- **Database Lock / Busy Error**: Database operates in SQLite WAL mode with `busy_timeout=10000ms` and `retries=3`.
- **Packet Queue Overflow**: Overflow packets dropped gracefully; drop counter (`dropped_count`) increments; status report alerts user in TUI header.
