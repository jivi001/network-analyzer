# Data Exporter & Importer (`storage/exporter.py` & `importer.py`)

## 1. Exporter (`storage/exporter.py`)

`storage/exporter.py` exports captured network packets, detection alerts, and session summaries into CSV, JSON, or PCAP formats.

### Path Traversal Protection
All export filename paths are sanitized using `_sanitize_export_path(filename, default_ext)`:
- Strips leading/trailing whitespace.
- Prevents directory traversal vectors (`../`, `..\\`).
- Enforces placement strictly inside the configured `export_directory` (default: `"exports"`).

### Supported Formats

#### A. CSV Export (`export_csv`)
Outputs tabular CSV containing:
`Timestamp, Source IP, Source Port, Destination IP, Destination Port, Protocol, Length, Service, Flags, Info`.

#### B. JSON Export (`export_json`)
Outputs structured JSON document containing:
- Session metadata (ID, start time, packet count, total bytes).
- Array of decoded packet dictionaries.
- Optional raw hex payloads if `config.yaml` (`json_include_payload`) is set to `true`.

#### C. PCAP Streaming (`PcapWriter` & `export_pcap`)
- `PcapWriter`: Implements thread-safe packet writing to an offline `.pcap` file using Scapy's `scapy.PcapWriter`.
- Bounded packet streaming ensures raw Ethernet packets are safely persisted without keeping large packet buffers in RAM.

---

## 2. Importer (`storage/importer.py`)

`storage/importer.py` validates and imports previously exported session JSON files into the database.

### Strict Schema Validation
Before inserting imported data:
- Validates existence of required keys (`session_type`, `start_time`, `packets`).
- Validates data types (e.g. `packet_count` must be non-negative integer).
- Rejects malformed or corrupted JSON documents with explicit `ValueError` messages.
- Operates inside an atomic database transaction (rolls back all changes if any packet row fails insertion).
