# Complete Application Lifecycle & Deterministic Shutdown

Detailed breakdown of startup initialization, runtime execution loops, and the deterministic shutdown sequence.

## 1. Startup Lifecycle

```text
1. CLI Argument Parsing (parse_args)
2. Load Configuration (config.yaml)
3. Initialize Privacy Filter (PrivacyFilter)
4. Privilege & Dependency Check (check_privileges, check_npcap_installed, check_nmap_installed)
5. Initialize Database (Database, WAL mode setup, Schema DDL)
6. Launch TUI Main Controller Loop (sentinel.py -> main)
```

---

## 2. Deterministic Shutdown Lifecycle

When the user requests exit or presses `Q` during live capture, `my-sentinel` executes a strict deterministic shutdown sequence to prevent corrupting database handles, PCAP streams, or background threads:

```text
       1. STOP CAPTURE PRODUCER (PacketSniffer.stop())
                        ↓
       2. STOP NEW QUEUE INSERTION (Set stopping flag)
                        ↓
       3. DRAIN QUEUE UNTIL EMPTY (Process remaining queued items)
                        ↓
       4. FLUSH ALERT BATCH (Persist pending alerts to SQLite DB)
                        ↓
       5. FLUSH PCAP STREAM (Close & flush Scapy PcapWriter handle)
                        ↓
       6. SAVE SESSION RECORD (Database.end_session, status='completed')
                        ↓
       7. STOP WORKER THREADS (Stop StatsAggregator rate calculator)
                        ↓
       8. CLOSE DATABASE HANDLES (Safely close SQLite connection pool)
                        ↓
       9. CLEAN TEMP FILES (Remove unneeded scratch or temporary files)
```
