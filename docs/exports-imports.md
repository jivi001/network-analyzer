# Data Exporter & Importer (`storage/exporter.py` & `importer.py`)

## 1. Format-Specific Exporter (`storage/exporter.py`)

`storage/exporter.py` exports live capture data, offline PCAP forensics, security alerts, and host discovery records into format-specific outputs: `.pcap`, `.csv`, or `.json`.

### Path Traversal Protection
All export paths are sanitized and validated using `Exporter.validate_export_path(filepath, export_dir)`:
- Strips leading/trailing whitespace.
- Prevents directory traversal attacks (`..`).
- Blocks absolute root paths (`/etc/passwd`, `C:\Windows\system32`).
- Enforces placement inside the configured `export_directory` (default: `"exports"`) or validated subfolders.
- Enforces format extension allowlists (`.pcap`, `.csv`, `.json`).

---

### Supported Export Formats

#### A. Raw Binary PCAP Export (`export_pcap`)
- Extracts raw Scapy packet binaries from `PacketInfo` objects.
- Uses Scapy's `wrpcap()` / `PcapWriter` to produce standard binary PCAP captures.
- **Verification**: Fully compatible with and readable by Wireshark, tcpdump, and Scapy (`rdpcap()`).

#### B. Structured CSV Export (`export_csv`)
- Produces RFC 4180 standard comma-separated values with minimal quoting.
- **Packet Stream Format**: `id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, length, service, info`
- **Security Alerts Format**: `id, timestamp, severity, rule_name, message, src_ip, dst_ip, dst_port, protocol`

#### C. Machine-Readable JSON Export (`export_json`)
- Produces fully serialized JSON with structured fields:
  - `metadata`: `application`, `version`, `exported_at`, `total_packets`, `total_alerts`, `total_hosts`.
  - `stats`: `total_packets`, `total_bytes`, `elapsed_seconds`, `packets_per_sec`, `bytes_per_sec`, `unique_hosts`, `protocol_counts`, `top_talkers`.
  - `alerts`: List of serializable alert objects.
  - `hosts`: List of discovered hosts with IP, MAC, hostname, open ports, and services.
  - `packets`: Optional list of decoded packet records.

---

## 2. Importer (`storage/importer.py`)

`storage/importer.py` validates and imports previously exported session JSON files into the SQLite database with strict validation and transaction safety.

### Intelligent Path & Directory Handling
- **Path Sanitization**: Strips surrounding whitespace and matching quotes (e.g. `"./exports/export.json"`).
- **Directory Inspection**: If a directory path is provided (e.g. `./exports/`), the application automatically discovers `.json` files in that folder and presents them as numbered selectable options (`[1] export_1.json`, `[2] export_2.json`).
- **Typo Recovery**: If a missing file is requested, intelligent fuzzy matching suggests close candidates in candidate directories.
- **Extension Enforcement**: Rejects non-`.json` files (e.g. `.pcap`, `.csv`, `.txt`) with explicit feedback before parsing.

### Strict Schema Validation & Transaction Safety
Before inserting imported data:
- Validates root JSON object structure and presence of recognized sections (`metadata`, `stats`, `alerts`, `hosts`, `packets`, `session`).
- Validates data types (`alerts` and `hosts` as arrays, `stats` and `metadata` as dictionaries).
- Rejects malformed JSON syntax or incompatible schemas with descriptive errors.
- **Transaction Safety**: Validates and constructs all internal models in-memory before acquiring database locks; executes inserts within an atomic transaction.
- **Duplicate & Session Isolation**: Creates a new session of type `session_type="imported"` linked to the imported metadata, saving alerts and discovered hosts safely without ID collisions.
- **Import Metrics Reporting**: Returns an `ImportResult` summarizing session ID, total records, alerts, hosts, and packet counts.
