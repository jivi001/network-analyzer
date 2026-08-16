# Functionality-to-Implementation Map

Mapping user-visible application features directly to underlying Python source files, controllers, and functions.

| User Feature / Functionality | Entry Point | Controller / Function | Source File | Output / Data Target |
|------------------------------|-------------|-----------------------|-------------|----------------------|
| **Live Packet Capture** | Main Menu `[1]` or `--capture` | `run_live_capture()` | [`sentinel.py`](../sentinel.py) | TUI Dashboard, `PcapWriter`, SQLite `sessions` table |
| **Packet Capture Engine** | `run_live_capture` | `PacketSniffer.start()` | [`core/sniffer.py`](../core/sniffer.py) | Bounded Queue (`queue.Queue`) |
| **Packet Layer Decoder** | Capture Loop | `process_packet()` | [`core/processor.py`](../core/processor.py) | `PacketInfo` Dataclass |
| **Metric Aggregation** | Capture Loop | `StatsAggregator.update()` | [`core/stats.py`](../core/stats.py) | `StatsSnapshot` Dataclass |
| **Rate Calculation (EMA)** | Background Thread | `StatsAggregator._calc_loop()` | [`core/stats.py`](../core/stats.py) | `packets_per_sec`, `bytes_per_sec` |
| **Signature Rule Evaluation** | Capture Loop | `RuleEngine.evaluate()` | [`detection/rule_engine.py`](../detection/rule_engine.py) | `AlertInfo` Dataclass list |
| **DNS Exfiltration Analysis** | Capture Loop | `AnomalyDetector.check_dns_exfiltration()` | [`detection/anomaly.py`](../detection/anomaly.py) | `AlertInfo` (`CRITICAL`) |
| **Port Scan Detection** | Capture Loop | `AnomalyDetector.check_port_scan()` | [`detection/anomaly.py`](../detection/anomaly.py) | `AlertInfo` (`HIGH`) |
| **ARP Spoof Monitoring** | Capture Loop | `ArpMonitor.check()` | [`detection/arp_monitor.py`](../detection/arp_monitor.py) | `AlertInfo` (`CRITICAL`) |
| **Target Network Scan (12 Profiles)** | Main Menu `[2]` or `--scan` | `NetworkScanner.scan()` | [`core/scanner.py`](../core/scanner.py) | `ScanResult`, SQLite `scan_results` & `hosts` tables |
| **Offline PCAP Forensics** | Main Menu `[3]` or `--pcap` | `run_pcap_analysis()` | [`sentinel.py`](../sentinel.py), [`tui/pcap_view.py`](../tui/pcap_view.py) | Forensic Summary Screen, SQLite |
| **History & Audit Viewer** | Main Menu `[4]` | `run_history()` | [`sentinel.py`](../sentinel.py), [`tui/history_view.py`](../tui/history_view.py) | Sessions, Alerts, & Hosts Tables |
| **CSV / JSON / PCAP Export** | Live Capture Keypress `E` / PCAP prompt | `export_csv()`, `export_json()`, `export_pcap()` | [`storage/exporter.py`](../storage/exporter.py) | Files in `exports/` folder |
| **Session JSON Import** | History Menu `[5]` | `Importer.import_json()` | [`storage/importer.py`](../storage/importer.py) | Database SQLite insertion & rollback |
| **Traffic Benchmark Generator** | CLI `traffic_lab.py` | `do_internet_action()`, `local_or_lan()` | [`traffic_lab.py`](../traffic_lab.py) | Real traffic generation & metrics |
