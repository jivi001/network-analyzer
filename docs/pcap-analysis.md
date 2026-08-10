# Offline PCAP Forensic Analysis (`tui/pcap_view.py`)

## 1. Overview

`my-sentinel` supports offline forensic analysis of saved PCAP (`.pcap`, `.pcapng`) capture files via Option `[3]` in the main menu or the CLI `--pcap <path>` option.

---

## 2. PCAP Processing Pipeline

```text
  User Selects PCAP File (e.g. capture.pcap)
                     │
                     ▼
            scapy.PcapReader(filepath)
                     │
         Packet Iteration Loop
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
  process_packet()        StatsAggregator.update()
        │                         │
        ▼                         ▼
  Pipeline Evaluate         Protocol Counts & Talkers
        │                         │
        ▼                         ▼
   AlertManager           StatsSnapshot Output
        │                         │
        └────────────┬────────────┘
                     ▼
          Rich Forensic Summary Display
                     │
                     ▼
          Save Session & Alerts to SQLite DB
```

---

## 3. Forensic Output Overview

Upon completing PCAP analysis, `display_pcap_analysis()` renders:
1. **File Metadata Panel**: File path, total packets parsed, total byte volume, elapsed analysis time.
2. **Protocol Breakdown Table**: Counts and percentages of TCP, UDP, ICMP, DNS, ARP, and HTTP/HTTPS traffic.
3. **Top Talkers Table**: Top 5 source and destination IP addresses by packet count and byte transfer volume.
4. **Detected Alerts Table**: Summary of all security threats detected in the PCAP file.

---

## 4. Error Handling & Validation

- Verifies file existence using `os.path.exists(filepath)`.
- Wraps Scapy packet reading in `try...except` blocks; corrupted or truncated packets increment an error counter without crashing the parser.
- Finalizes session record in database marked with `session_type="pcap_analysis"`.
