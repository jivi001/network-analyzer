# Offline PCAP Forensic Analysis (`core/pcap_loader.py` & `tui/pcap_view.py`)

## 1. Overview

`my-sentinel` supports comprehensive offline forensic analysis of saved capture files (`.pcap`, `.pcapng`, `.cap`) via Option `[3]` in the main menu or the CLI `--pcap <path>` option.

---

## 2. PCAP Processing Pipeline

```text
  User Selects PCAP File (e.g. exports/test1.pcap)
                     │
                     ▼
          Path Validation & Fuzzy Typos Matcher
          (utils/path_helpers.py)
                     │
                     ▼
             scapy.PcapReader(filepath)
                     │
          Constant-RAM Streaming Loop
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
  process_packet()        StatsAggregator.update()
  (IPv4/IPv6/ARP/DNS)     (First/Last Timestamps)
        │                         │
        ▼                         ▼
  Pipeline Evaluate       Protocol Counts, Top Talkers,
  (Rules, Entropy, ARP)   & Top Conversations
        │                         │
        ▼                         ▼
   AlertManager           StatsSnapshot Output
  (Historical Alerts)     (True Forensic Duration & PPS)
        │                         │
        └────────────┬────────────┘
                     ▼
          Rich Forensic Summary Display
          (Forensic Panel, Protocols, Conversations, Alerts)
                     │
                     ▼
          Save Session & Alerts to SQLite Database
                     │
                     ▼
          Optional Export (PCAP, CSV, JSON)
```

---

## 3. Forensic Output & Metrics

Upon completing PCAP analysis, `display_pcap_analysis()` renders:

1. **PCAP Forensic Summary Panel**:
   - Total Packets and Total Byte Volume.
   - Forensic Capture Duration computed from true packet timestamps ($t_{\text{last}} - t_{\text{first}}$).
   - Forensic Throughput Rates (`packets/sec` and `bytes/sec`).
   - Average Packet Size and Unique Host count.
2. **Protocol Breakdown Table**:
   - Counts, exact percentages, and visual distribution bars for TCP, UDP, ICMP, DNS, ARP, IPv6, etc.
3. **Top Network Conversations Table**:
   - Canonical `Endpoint A` $\leftrightarrow$ `Endpoint B` communication pairs sorted by volume.
4. **Top Data Sources (Talkers)**:
   - Top IP addresses ranked by transmitted bytes and packet count.
5. **Flagged Security Threats Table**:
   - All retroactive detections (DNS exfiltration, ARP spoofing, port scans, YAML signature matches).

---

## 4. Intelligent Path Validation & UX Features

The path prompt (`prompt_pcap_path`) features:
- **Quote Stripping**: Safely unquotes drag-and-drop or pasted paths (e.g. `"./exports/test1.pcap"` $\rightarrow$ `./exports/test1.pcap`).
- **Path Normalization**: Cross-platform path resolution supporting absolute paths, relative paths (`exports\test1.pcap`, `exports/test1.pcap`), and forward/backward slashes.
- **Numbered Quick-Selection**: Automatically lists available PCAP captures in `exports/` and the current working directory, allowing single-digit selection (e.g. `1`, `2`).
- **Did You Mean? Typo Matcher**: Searches the target folder for close filename matches using `difflib` when a user mistypes a filename (e.g. `tast1.pcap` $\rightarrow$ suggests `test1.pcap`) and prompts for one-key selection.

---

## 5. Precise Error Classification

The system distinguishes between distinct failure modes:
- **Missing File**: `PCAP file not found: '<path>'`
- **Directory Provided**: `Path is a directory, not a PCAP file: '<path>'`
- **Empty File**: `PCAP file is empty (0 bytes): '<path>'`
- **Corrupted Capture**: `Corrupt or invalid PCAP format in '<path>': <details>`
- **Unsupported Link Type**: Detailed Scapy layer error reporting.
