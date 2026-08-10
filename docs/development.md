# Developer Guide & Repository Structure

Guidelines for maintaining, building, and extending `my-sentinel`.

## 1. Project Organization Map

```text
network-analyzer/
├── sentinel.py              → Application CLI entry point & TUI main loop
├── config.yaml              → Master configuration file
├── pyproject.toml           → Package build metadata & script entry points
├── requirements.txt         → Third-party dependencies
├── install.ps1              → Windows PowerShell installation script
├── install.bat              → Batch installer launcher
├── sentinel_data.db         → Default SQLite audit database
│
├── core/                    → Core Packet Processing & Scanning
│   ├── sniffer.py           → Scapy raw capture engine & background thread
│   ├── processor.py         → Packet layer decoder & PacketInfo builder
│   ├── scanner.py           → Nmap scanner integration & 12 scan profiles
│   └── stats.py             → Thread-safe metric aggregator & rate calc
│
├── detection/               → Multi-Vector Security Detection Engine
│   ├── pipeline.py          → Packet detection pipeline coordinator
│   ├── rule_engine.py       → Signature-based YAML rule evaluator
│   ├── anomaly.py           → Shannon entropy DNS exfil & port scan detector
│   ├── arp_monitor.py       → ARP spoofing & MAC binding state machine
│   └── alerts.py            → Ring-buffer alert memory & DB persistence
│
├── network/                 → Network Intelligence & Lookups
│   ├── resolver.py          → Thread-safe reverse DNS resolver with cache
│   ├── whois_lookup.py      → WHOIS ASN/Org lookup engine
│   └── traceroute.py        → Active ICMP/UDP route traceroute
│
├── storage/                 → Database & Import/Export Layer
│   ├── database.py          → SQLite database layer (WAL mode)
│   ├── models.py            → Standardized Dataclasses
│   ├── exporter.py          → CSV, JSON, and PCAP exporter streams
│   └── importer.py          → Session JSON validator & transactional importer
│
├── tui/                     → Rich Terminal User Interface
│   ├── dashboard.py         → Live dashboard screen view renderer
│   ├── menu.py              → Interactive menus & user input prompts
│   ├── scan_view.py         → Network scan progress & results tables
│   ├── pcap_view.py         → Offline PCAP analysis results screen
│   ├── history_view.py      → History menu & session audit viewer
│   └── helpers.py           → Table formatters, badges, & progress bars
│
├── utils/                   → Core Utilities & Shared State
│   ├── console.py           → Single shared Rich Console instance owner
│   ├── constants.py         → Service ports, colors, severity definitions
│   ├── privacy.py           → IP address masking filter
│   └── privileges.py        → Administrator check & dependency verifiers
│
├── rules/                   → Signature Detection Rules
│   └── default_rules.yaml   → YAML signature detection rules file
│
├── tests/                   → Automated Test Suite
│   ├── test_audit_regressions.py  → Security & hardening regression tests
│   └── test_subsystem_stress.py   → Subsystem stress & concurrency tests
│
└── docs/                    → Complete Knowledge Base & Documentation
```

---

## 2. Coding Standards & Principles

1. **Strict Type Annotations**: Use Python `typing` hints (`Optional`, `List`, `Dict`, `Set`, `Tuple`) on all public function and method signatures.
2. **Thread Safety**: All state modified across threads must be guarded by locks (`threading.Lock` or `threading.RLock`).
3. **Single Console Instance**: Never instantiate a new `Console()` object in sub-modules. Import `from utils.console import console`.
4. **No Arbitrary Commands**: Never invoke raw shell commands via `os.system` or `subprocess(shell=True)`.
