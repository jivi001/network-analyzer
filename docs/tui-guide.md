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
│   [6]  Exit                                            │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## 2. Live Capture Dashboard Screen

The live capture screen uses a split layout:
- **Header Panel**: Subsystem status, NIC interface, elapsed capture time, paused indicator.
- **Left Panel (Packet Stream)**: Real-time packet stream listing `#`, Time, Source, Destination, Protocol, Length, Service, and Info. Dynamically sized to terminal height with slice-based rendering.
- **Right Top Panel (Protocol Distribution)**: Protocol breakdown badges (`TCP`, `UDP`, `ICMP`, `DNS`, `ARP`) with percentage bar charts.
- **Right Bottom Panel (Top Talkers)**: Top 5 source/destination IP addresses by byte volume and packet count.
- **Threat Alerts Panel**: Live security alerts feed highlighting flagged threats (DNS exfiltration, ARP spoofing, port scans, signature matches) and degraded subsystem warnings.
- **Footer Telemetry Bar**: Comprehensive real-time system & network metrics:
  ```text
  Cap: 1,420 (50.0/s) | Proc: 1,420 (50.0/s) | Drop: 0 | Queue: 0/10000 | CPU: 2% | RAM: 79.1MB | Health: HEALTHY
  ```

---

## 3. Keyboard Shortcut Reference

| Key | Context | Action |
|-----|---------|--------|
| **`P`** | Live Capture | Pauses or resumes TUI view updating. Packet capture continues in background. |
| **`F`** | Live Capture | Suspends `Live` view, opens interactive prompt to enter a new BPF filter, validates filter, and restarts capture. |
| **`E`** | Live Capture | Suspends `Live` view, prompts for export format (CSV, JSON, PCAP) and output path, writes file. |
| **`Q`** | Live Capture | Triggers deterministic shutdown sequence (stop sniffer -> drain queue -> flush alert batch -> flush PCAP -> save session summary -> stop workers -> close DB). |
| **`Q` / `6`** | Main Menu | Returns to previous menu level or cleanly exits application. |

---

## 4. Metric Definitions & Formulas

| Metric | Source | Calculation / Definition |
|--------|--------|--------------------------|
| **Capture Rate (Cap PPS)** | `sentinel.py:run_live_capture` | Rate of raw packets received at the sniffer socket: $\frac{\Delta captured}{\Delta t}$. |
| **Processing Rate (Proc PPS)** | `StatsAggregator._calc_loop` | Exponential moving average (`alpha=0.5`): $PPS = 0.5 \times PPS_{old} + 0.5 \times \frac{\Delta processed}{\Delta t}$. |
| **Bytes/sec (BPS)** | `StatsAggregator._calc_loop` | Exponential moving average (`alpha=0.5`): $BPS = 0.5 \times BPS_{old} + 0.5 \times \frac{\Delta bytes}{\Delta t}$. |
| **Dropped Packets** | `run_live_capture` | Counter incremented when `packet_queue.put_nowait()` raises `queue.Full`. |
| **Queue Depth** | `packet_queue.qsize()` | Instantaneous number of packets waiting in thread queue for processing. |
| **Queue Utilization** | `(qsize / maxsize) * 100` | Percentage of processing queue capacity in use (warns if > 70%). |
| **CPU Utilization (%)** | `StatsAggregator` | Process CPU execution time over wall-clock time delta. |
| **Memory (MB)** | `StatsAggregator` | Process working set size sampled via Windows OS `GetProcessMemoryInfo` or Unix `getrusage`. |
| **Entropy (bits/char)**| `AnomalyDetector._shannon_entropy` | $H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$ evaluated over DNS subdomains. |
