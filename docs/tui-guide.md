# TUI User Guide & Metric Definitions

`my-sentinel` features a high-performance terminal user interface built with Rich (`rich.live.Live`, `rich.layout.Layout`, `rich.table.Table`, `rich.panel.Panel`).

## 1. Main Menu Layout

```text
┌────────────────────────────────────────────────────────┐
│                   my-sentinel v1.0.0                   │
│           Network Traffic Analyzer & Scanner           │
├────────────────────────────────────────────────────────┤
│                                                        │
│   [1]  Live Capture                                    │
│   [2]  Network Scan                                    │
│   [3]  Analyze PCAP File                               │
│   [4]  View History                                    │
│   [5]  Settings                                        │
│   [Q]  Exit                                            │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## 2. Live Capture Dashboard Screen

The live capture screen uses a split layout:
- **Header Panel**: Subsystem status, NIC interface, BPF filter, capture state, health indicator (`HEALTHY` / `DEGRADED`).
- **Stats Panel**: Real-time throughput (pack/s, bytes/s), total volume, drop count, queue utilization.
- **Protocol & Security Panel**: Protocol breakdown badges (`TCP`, `UDP`, `ICMP`, `DNS`, `ARP`), active threat alert alerts table.
- **Packet Streaming Table**: Live ring-buffer table listing time, src/dst IPs, ports, protocol, length, and decoded flags/info.

---

## 3. Keyboard Shortcut Reference

| Key | Context | Action |
|-----|---------|--------|
| **`P`** | Live Capture | Pauses or resumes TUI view updating. Packet capture continues in background. |
| **`F`** | Live Capture | Stops `Live`, opens prompt to enter a new BPF filter, restarts capture with new filter. |
| **`E`** | Live Capture | Stops `Live`, prompts for export format (CSV, JSON, PCAP) and output path, writes file. |
| **`Q`** | Live Capture | Triggers deterministic shutdown sequence (stop producer -> drain queue -> flush alert batch -> flush PCAP -> save session -> stop workers -> close DB). |
| **`Q` / `0`** | Menus | Returns to previous menu level or exits application. |

---

## 4. Metric Definitions & Formulas

| Metric | Source | Calculation / Definition |
|--------|--------|--------------------------|
| **Packets/sec (PPS)** | `StatsAggregator._calc_loop` | Exponential moving average (`alpha=0.5`): `PPS = 0.5 * PPS_old + 0.5 * (Δpackets / Δt)`. |
| **Bytes/sec (BPS)** | `StatsAggregator._calc_loop` | Exponential moving average (`alpha=0.5`): `BPS = 0.5 * BPS_old + 0.5 * (Δbytes / Δt)`. |
| **Dropped Packets** | `run_live_capture` | Counter incremented when `packet_queue.put_nowait()` raises `queue.Full`. |
| **Queue Depth** | `packet_queue.qsize()` | Instantaneous number of packets waiting in thread queue for processing. |
| **Queue Utilization** | `(qsize / maxsize) * 100` | Percentage of processing queue capacity in use (warns if > 80%). |
| **Entropy (bits/char)**| `AnomalyDetector._shannon_entropy` | $H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$ evaluated over DNS subdomains. |
