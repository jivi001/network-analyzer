# Automated Testing & Verification Guide

`my-sentinel` includes a comprehensive regression, security, stress, forensic, and end-to-end integration test suite built on `pytest` and `pytest-cov`.

## 1. Test Suite Commands

- **Test Automation**: Pytest suite (`pytest-cov`) with **235 automated tests** across 20 test modules.
- **Coverage**: **81% overall statement coverage** with 90%+ across core security, models, database, and telemetry engines.
- **Execution Speed**: Full suite executes in **~16 seconds**.

Run the full automated test suite with coverage:

```powershell
.venv\Scripts\python.exe -m pytest --cov=core --cov=detection --cov=storage --cov=tui --cov=utils --cov=traffic_lab --cov-branch --cov-report=term-missing
```

Or run standard `pytest` directly:

```powershell
.venv\Scripts\python.exe -m pytest tests/ -v
```

---

## 2. Test Suite Breakdown (235 Total Tests)

| Test File | Focus & Subsystem Coverage | Test Count |
|-----------|----------------------------|------------|
| [`tests/test_audit_regressions.py`](../tests/test_audit_regressions.py) | Security hardening regressions: BPF filter validation, target validation, SQLite persistence/recovery, path traversal, rule engine deduplication, pipeline exception isolation. | 14 |
| [`tests/test_coverage_arp_and_alerts.py`](../tests/test_coverage_arp_and_alerts.py) | Deep ARP monitor TTL eviction, maximum hosts capacity limits, AlertManager FIFO queue pruning, and concurrent alert deduplication. | 5 |
| [`tests/test_coverage_history_and_storage.py`](../tests/test_coverage_history_and_storage.py) | History sub-menu interactive selection, session/alert/host rich tables, and exporter JSON with packet payload streams. | 6 |
| [`tests/test_coverage_menu_interactive.py`](../tests/test_coverage_menu_interactive.py) | Interactive menu option routing, capture/scan settings prompts, PCAP/JSON path entry, and export configuration. | 6 |
| [`tests/test_coverage_privileges_and_env.py`](../tests/test_coverage_privileges_and_env.py) | Cross-platform privilege checks (Windows admin / Linux UID 0), Nmap binary discovery in PATH, and Npcap driver detection. | 5 |
| [`tests/test_coverage_rules_and_export_deep.py`](../tests/test_coverage_rules_and_export_deep.py) | Detection rule condition branches (`cleartext`, `high_port`, `mac_change`), dynamic rule reloading, and raw PCAP packet layer writers. | 6 |
| [`tests/test_coverage_scan_view.py`](../tests/test_coverage_scan_view.py) | Scan view rendering: progress panels, scan summaries, host tables, port/service breakdowns, and empty result handling. | 3 |
| [`tests/test_coverage_sentinel_cli.py`](../tests/test_coverage_sentinel_cli.py) | CLI argument parser (`--capture`, `--scan`, `--pcap`, `--mask`), live capture worker loop, scan/pcap/history workflows, and graceful exit. | 12 |
| [`tests/test_coverage_stats_advanced.py`](../tests/test_coverage_stats_advanced.py) | Telemetry sampling, process memory measurement across OS platforms, protocol distribution percentages, EMA rate calculations, and reset semantics. | 6 |
| [`tests/test_coverage_traffic_lab_comprehensive.py`](../tests/test_coverage_traffic_lab_comprehensive.py) | TCP/UDP action dispatchers, chunked HTTPS clients, DNS query packets, interval worker scheduling, and rate validation invariants. | 8 |
| [`tests/test_coverage_utils_deep.py`](../tests/test_coverage_utils_deep.py) | IP/MAC/Text privacy masking levels, alternate screen buffer TTY control, signal handling, and path similarity matching. | 11 |
| [`tests/test_dns_exfiltration_hardening.py`](../tests/test_dns_exfiltration_hardening.py) | Shannon entropy DNS exfiltration analysis, subdomain length boundary conditions, sliding multi-signal correlation, malformed DNS packet resilience. | 6 |
| [`tests/test_e2e_comprehensive_validation.py`](../tests/test_e2e_comprehensive_validation.py) | End-to-end integration: sniffer start/stop 50-cycle stability, database persistence, packet layer decoding, decoupled worker lifecycle. | 9 |
| [`tests/test_e2e_workflows.py`](../tests/test_e2e_workflows.py) | Full multi-stage integration pipelines: **Workflows A through E** (live capture roundtrip, PCAP reload, CSV export validation, JSON import history, Traffic lab rate accounting). | 5 |
| [`tests/test_json_import_validation_and_ux.py`](../tests/test_json_import_validation_and_ux.py) | JSON import schema validation, directory inspection, numbered file selection, atomic transaction rollbacks, structured `ImportResult`. | 11 |
| [`tests/test_nmap_expansion.py`](../tests/test_nmap_expansion.py) | All 12 Nmap scan profiles, argument generation, timeout enforcement, custom arg allowlists, target input validation, model normalization. | 9 |
| [`tests/test_pcap_path_validation_and_ux.py`](../tests/test_pcap_path_validation_and_ux.py) | PCAP path resolution, quote stripping, Windows backslash handling, fuzzy "Did you mean?" typo matcher, numbered quick selection. | 13 |
| [`tests/test_pcap_tui_rendering_responsive.py`](../tests/test_pcap_tui_rendering_responsive.py) | PCAP forensic layout responsiveness across `80x24`, `100x30`, `120x40`, `160x50` viewport bounds, CP1252-safe ASCII bars. | 8 |
| [`tests/test_reliability_offline_pcap_export.py`](../tests/test_reliability_offline_pcap_export.py) | Traffic lab rate pacing, truthful attempt accounting, offline PCAP forensics (duration & rates), binary PCAP/CSV/JSON format exports, system telemetry. | 13 |
| [`tests/test_screen_lifecycle_contract.py`](../tests/test_screen_lifecycle_contract.py) | Single-owner console singleton, `ScreenState` state transitions, `\033[3J` scrollback clearing, Live display suspension across interactive prompts. | 5 |
| [`tests/test_subsystem_stress.py`](../tests/test_subsystem_stress.py) | AlertManager multithreading, AnomalyDetector memory bounds, Sniffer state machine, Rich markup escaping, SQLite multithreading & SQL injection resilience. | 17 |
| [`tests/test_tui_stability_regressions.py`](../tests/test_tui_stability_regressions.py) | Dynamic table sizing, 100% queue saturation health, snapshot isolation under high concurrency, untrusted markup escaping. | 4 |
| [`tests/test_unit_core.py`](../tests/test_unit_core.py) | Core subsystem unit tests: StatsAggregator, PacketProcessor, PacketSniffer, NetworkScanner, PcapLoader. | 13 |
| [`tests/test_unit_detection.py`](../tests/test_unit_detection.py) | Detection subsystem unit tests: AlertManager, AnomalyDetector, ArpMonitor, RuleEngine, PacketDetectionPipeline. | 9 |
| [`tests/test_unit_storage_database.py`](../tests/test_unit_storage_database.py) | SQLite database unit tests: sessions, alert batching, host inventory, and Exporter path traversal validation. | 6 |
| [`tests/test_unit_traffic_lab.py`](../tests/test_unit_traffic_lab.py) | Traffic lab unit tests: atomic accounting, input validation, dispatchers, rate boundary rules. | 4 |
| [`tests/test_unit_tui.py`](../tests/test_unit_tui.py) | TUI component unit tests: LiveDashboard, formatting helpers, badges, and history tables. | 9 |
| [`tests/test_unit_utils.py`](../tests/test_unit_utils.py) | Utility unit tests: PrivacyFilter, ScreenManager, privilege diagnostics, constants, path helpers. | 12 |

**Total Suite Coverage: 235 Passing Tests in ~16.2 Seconds.**

---

## 3. End-to-End Workflows Covered

### Workflow A: Live Capture Pipeline Roundtrip
Synthetic Scapy packets $\to$ decoding via `process_packet` $\to$ multi-vector detection $\to$ metric aggregation $\to$ SQLite session storage $\to$ JSON export $\to$ JSON import $\to$ session search.

### Workflow B: Offline PCAP Forensic Analysis & Re-Export
Synthetic PCAP creation $\to$ constant-memory streaming ingestion $\to$ protocol distribution & talker extraction $\to$ binary PCAP re-export $\to$ Wireshark-compatible reload verification.

### Workflow C: PCAP to Forensic CSV Export
Offline PCAP loading $\to$ tabular metric aggregation $\to$ RFC 4180 CSV serialization $\to$ header and column validation.

### Workflow D: PCAP to JSON Database Migration
Offline PCAP analysis $\to$ machine-readable JSON export $\to$ transactional schema import $\to$ database session retrieval.

### Workflow E: Controlled Traffic Benchmark Generation
Request dispatching $\to$ rate limiting $\to$ truthful attempt/success/timeout accounting $\to$ real-time metrics.
