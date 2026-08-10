# SQLite Database Layer & Schema (`storage/database.py`)

## 1. Subsystem Architecture

`storage/database.py` manages persistent storage using SQLite. The database connection is configured with **Write-Ahead Logging (WAL)** mode and a `busy_timeout=10000ms` to guarantee thread safety and prevent lock contention during concurrent reads and writes.

---

## 2. Schema DDL & Table Specifications

```sql
-- 1. Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_type TEXT NOT NULL,       -- 'capture', 'scan', 'pcap_analysis'
    start_time TEXT NOT NULL,
    end_time TEXT,
    packet_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    interface TEXT,
    filter_applied TEXT,
    status TEXT DEFAULT 'active',     -- 'active', 'completed', 'interrupted'
    target TEXT                       -- Target IP/subnet for scan sessions
);

-- 2. Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    timestamp REAL NOT NULL,
    timestamp_str TEXT NOT NULL,
    severity TEXT NOT NULL,          -- 'INFO', 'WARNING', 'HIGH', 'CRITICAL'
    rule_name TEXT NOT NULL,
    message TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER DEFAULT 0,
    protocol TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- 3. Discovered Hosts Table
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    open_ports TEXT,                 -- JSON array of open ports
    services TEXT,                   -- JSON object of services
    os_guess TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT,                     -- 'nmap', 'capture', 'manual'
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    state TEXT DEFAULT 'up'
);

-- 4. Scan Results Table
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    scan_args TEXT,
    hosts_found INTEGER DEFAULT 0,
    start_time TEXT NOT NULL,
    end_time TEXT,
    duration_sec REAL DEFAULT 0.0,
    raw_output TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
```

---

## 3. Database Indexes

- `idx_alerts_session_id` ON `alerts(session_id)`
- `idx_alerts_severity` ON `alerts(severity)`
- `idx_hosts_ip` ON `hosts(ip_address)`
- `idx_scan_results_session_id` ON `scan_results(session_id)`

---

## 4. Key Database Methods

| Method | Purpose |
|--------|---------|
| `create_session(session)` | Inserts new session record; returns `session_id`. |
| `end_session(session_id, packet_count, total_bytes, alert_count)` | Updates session with final statistics, `end_time`, and sets `status='completed'`. |
| `save_alert(alert)` | Parameterized insert of `AlertInfo` object into `alerts` table. |
| `save_alerts_batch(alerts)` | Transactional `executemany` insert of alert batches. |
| `save_host(host)` | Upserts host record into `hosts` table (`ON CONFLICT(ip_address) DO UPDATE`). |
| `save_scan_result(result)` | Parameterized insert of `ScanResult` object into `scan_results` table. |
| `get_recent_sessions(limit)` | Fetches recent session records sorted by `id DESC`. |
| `get_session_alerts(session_id)` | Fetches all alerts belonging to a specific session. |
| `get_all_hosts()` | Fetches all discovered host records. |
