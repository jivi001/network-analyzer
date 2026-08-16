# Application Performance & Resource Bounds

Design patterns and resource management strategies that maintain system responsiveness and data integrity under high network loads.

## 1. Memory Bounding Architecture

To prevent out-of-memory (OOM) crashes during long-running high-throughput packet capture:

```text
               RAM BOUNDS
 ┌────────────────────────────────────┐
 │  Live TUI Buffer: 500 packets      │
 │  Processing Queue: 10,000 packets  │
 │  Max Alerts Buffer: 100 alerts     │
 └─────────────────┬──────────────────┘
                   │
                   ▼ (Streaming Persistence)
 ┌────────────────────────────────────┐
 │  Disk PCAP Stream / SQLite WAL     │
 └────────────────────────────────────┘
```

1. **Scapy Storage Control**: `scapy.sniff(store=0)` ensures raw packets are not accumulated in Scapy's internal memory list.
2. **Bounded Processing Queue**: `packet_queue = Queue(maxsize=10000)`. If the queue reaches 100% capacity during intense traffic bursts, excess packets are dropped gracefully without crashing and accurately counted (`dropped_count`).
3. **Bounded TUI Ring-Buffer**: `packets_buffer` ring-buffer in TUI maintains only the 500 most recent packets in RAM, with dynamic rendering slicing only the exact visible row height.
4. **Decoupled Worker Architecture**: Packet capture and layer decoding run in dedicated worker threads completely separate from Rich TUI rendering, ensuring render passes never delay packet ingress.
5. **Memory-Bounded Anomaly Detector**: `AnomalyDetector` caps tracked IP sliding windows (`_port_scan_tracker`) to a maximum of 1,000 active IPs using LRU eviction.

---

## 2. Dual Rate Tracking & Backlog Detection

`StatsAggregator` and `sentinel.py` calculate both:
1. **Capture Rate (`capture_pps`)**: Raw rate of packets arriving at the network socket interface.
2. **Processing Rate (`processing_pps`)**: Rate of packets decoded, inspected by detection engines, and stored.

### Exponential Moving Average (EMA, $\alpha = 0.5$):

$$PPS_{new} = 0.5 \times PPS_{old} + 0.5 \times \frac{\Delta packets}{\Delta t}$$

### Backlog Health Transition:
If $\text{capture\_pps} > 1.25 \times \text{processing\_pps}$ and queue depth accumulates beyond 100 packets, the system automatically transitions to `BACKLOG` / `DEGRADED` health state to notify the operator.

---

## 3. Sampled System Telemetry

Background system telemetry is sampled periodically (every 1 second) rather than per packet:
- **CPU Utilization (%)**: Process CPU time over wall-clock time delta.
- **Resident Memory (MB)**: Process working set size sampled via Windows `GetProcessMemoryInfo` or Unix `getrusage`.
- **Active Threads**: `threading.active_count()`.

---

## 4. SQLite Database WAL Mode & Pragmas

SQLite is initialized in `storage/database.py` with performance pragmas:

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
```

- **WAL Mode (Write-Ahead Logging)**: Allows concurrent read transactions while write operations execute in the background.
- **Batch Alert Persistence**: Alerts are batched and flushed to SQLite in chunks of up to 50 records, avoiding per-packet database lock overhead.
