# Functionality-to-Implementation Map

Mapping user-visible application features directly to underlying Python source files, controllers, and functions.

| User Feature / Functionality | Entry Point | Controller / Function | Source File | Output / Data Target |
|------------------------------|-------------|-----------------------|-------------|----------------------|
| **Live Packet Capture** | Main Menu `[1]` or `--capture` | `run_live_capture()` | [sentinel.py](file:///d:/Programs/Security/network-analyzer/sentinel.py#L250) | TUI Dashboard, `PcapWriter`, SQLite `sessions` table |
| **Packet Capture Engine** | `run_live_capture` | `PacketSniffer.start()` | [core/sniffer.py](file:///d:/Programs/Security/network-analyzer/core/sniffer.py#L43) | Bounded Queue (`queue.Queue`) |
| **Packet Layer Decoder** | Capture Loop | `process_packet()` | [core/processor.py](file:///d:/Programs/Security/network-analyzer/core/processor.py#L9) | `PacketInfo` Dataclass |
| **Metric Aggregation** | Capture Loop | `StatsAggregator.update()` | [core/stats.py](file:///d:/Programs/Security/network-analyzer/core/stats.py#L31) | `StatsSnapshot` Dataclass |
| **Rate Calculation (EMA)** | Background Thread | `StatsAggregator._calc_loop()` | [core/stats.py](file:///d:/Programs/Security/network-analyzer/core/stats.py#L127) | `packets_per_sec`, `bytes_per_sec` |
| **Signature Rule Evaluation** | Capture Loop | `RuleEngine.evaluate()` | [detection/rule_engine.py](file:///d:/Programs/Security/network-analyzer/detection/rule_engine.py#L70) | `AlertInfo` Dataclass list |
| **DNS Exfiltration Analysis** | Capture Loop | `AnomalyDetector.check_dns_exfiltration()` | [detection/anomaly.py](file:///d:/Programs/Security/network-analyzer/detection/anomaly.py#L50) | `AlertInfo` (`CRITICAL`) |
| **Port Scan Detection** | Capture Loop | `AnomalyDetector.check_port_scan()` | [detection/anomaly.py](file:///d:/Programs/Security/network-analyzer/detection/anomaly.py#L90) | `AlertInfo` (`HIGH`) |
| **ARP Spoof Monitoring** | Capture Loop | `ArpMonitor.check()` | [detection/arp_monitor.py](file:///d:/Programs/Security/network-analyzer/detection/arp_monitor.py#L25) | `AlertInfo` (`CRITICAL`) |
| **Target Network Scan** | Main Menu `[2]` or `--scan` | `NetworkScanner.scan()` | [core/scanner.py](file:///d:/Programs/Security/network-analyzer/core/scanner.py#L74) | `ScanResult`, SQLite `scan_results` & `hosts` tables |
| **Offline PCAP Analysis** | Main Menu `[3]` or `--pcap` | `run_pcap_analysis()` | [sentinel.py](file:///d:/Programs/Security/network-analyzer/sentinel.py#L650) | Forensic Summary Screen, SQLite |
| **History & Audit Viewer** | Main Menu `[4]` | `run_history_viewer()` | [tui/history_view.py](file:///d:/Programs/Security/network-analyzer/tui/history_view.py#L40) | Sessions, Alerts, & Hosts Tables |
| **CSV / JSON / PCAP Export** | Live Capture Keypress `E` | `export_csv()`, `export_json()`, `export_pcap()` | [storage/exporter.py](file:///d:/Programs/Security/network-analyzer/storage/exporter.py#L30) | Files in `exports/` folder |
| **Session JSON Import** | Database Import API | `import_session_json()` | [storage/importer.py](file:///d:/Programs/Security/network-analyzer/storage/importer.py#L20) | Database SQLite insertion |
