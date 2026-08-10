# Application Performance & Resource Bounds

Design patterns and memory management strategies that maintain system responsiveness under heavy network loads.

## 1. Memory Bounding Architecture

To prevent out-of-memory (OOM) crashes during long-running high-throughput packet capture:

```text
               RAM BOUNDS
 ┌────────────────────────────────────┐
 │  Live TUI Buffer: 500 packets      │
 │  Processing Queue: 5,000 packets   │
 │  Max Alerts Buffer: 100 alerts     │
 └─────────────────┬──────────────────┘
                   │
                   ▼ (Streaming Persistence)
 ┌────────────────────────────────────┐
 │  Disk PCAP Stream / SQLite WAL     │
 └────────────────────────────────────┘
```

1. **Scapy Storage Control**: `scapy.sniff(store=0)` ensures raw packets are not accumulated in Scapy's internal list.
2. **Bounded Processing Queue**: `packet_queue = Queue(maxsize=5000)`. If queue fills, excess packets are dropped gracefully and counted (`dropped_count`) rather than overwhelming RAM.
3. **Bounded TUI Ring-Buffer**: `packets_buffer` ring-buffer in TUI keeps only the 500 most recent packets in RAM for rendering.
4. **Memory-Bounded Anomaly Detector**: `AnomalyDetector` caps tracked IP sliding windows (`_port_scan_tracker`) to a maximum of 1,000 active IPs using LRU eviction.

---

## 2. Exponential Moving Average Rate Calculation

`StatsAggregator` calculates real-time throughput using Exponential Moving Average (EMA, $\alpha = 0.5$) updated once per second:

$$PPS_{new} = 0.5 \times PPS_{old} + 0.5 \times \frac{\Delta packets}{\Delta t}$$

$$BPS_{new} = 0.5 \times BPS_{old} + 0.5 \times \frac{\Delta bytes}{\Delta t}$$

This algorithm smooths packet burst spikes for clean TUI rendering without creating high CPU overhead.

---

## 3. SQLite Database WAL Mode & Pragmas

SQLite is initialized in `storage/database.py` with performance pragmas:

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=10000;
```

- **WAL Mode (Write-Ahead Logging)**: Allows concurrent read transactions while write operations execute in the background.
- **`synchronous=NORMAL`**: Provides write performance while preserving database integrity.
