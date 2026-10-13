# Data Exporter & Importer (`storage/exporter.py` & `importer.py`)

## 1. Format-Specific Exporter (`storage/exporter.py`)

`storage/exporter.py` exports live capture data, offline PCAP forensics, security alerts, and host discovery records into format-specific outputs: `.pcap`, `.csv`, or `.json`.

### Path Traversal & Containment Policy
All export paths are sanitized and validated using `Exporter.validate_export_path(filepath, export_dir, allow_absolute=False)`:
- **Whitespace Sanitization**: Strips leading and trailing whitespace and enclosing quotes.
- **Traversal Prevention**: Resolves `os.path.realpath` for both the export directory and the target path, preventing `..` bypasses.
- **Sibling Collision Defense**: Evaluates canonical parent directories to ensure the path is strictly contained within `export_dir`, preventing sibling directory collisions (e.g., `exports_evil/`).
- **Absolute Path Policy**: `allow_absolute=False` by default. Absolute paths outside `export_dir` are strictly rejected unless explicitly opted in by programmatic callers. User-facing TUI prompts always enforce `allow_absolute=False`.
- **System Directory Denylist**: Explicitly rejects paths located in root-level or critical operating system directories (`/etc`, `/bin`, `/sbin`, `/usr`, `/var`, `/boot`, `/dev`, `C:\Windows`, etc.).
- **Zero Pre-Validation Side Effects**: Directory creation (`os.makedirs`) is deferred until after path validation successfully completes.
- **Extension Enforcement**: Enforces format extension allowlists (`.pcap`, `.csv`, `.json`).

---

### Supported Export Formats & API Contracts

#### A. Raw Binary PCAP Export (`export_pcap(filepath, packets=None)`)
- Extracts raw Scapy packet binaries from `PacketInfo` objects.
- Uses Scapy's `wrpcap()` / `PcapWriter` to produce standard binary PCAP captures.
- Handles empty packet collections gracefully by producing a valid empty PCAP capture header.
- **Verification**: Fully compatible with and readable by Wireshark, tcpdump, and Scapy (`rdpcap()`).

#### B. Structured CSV Export (`export_csv(filepath, packets=None, alerts=None, stats=None)`)
- Produces RFC 4180 standard comma-separated values with minimal quoting.
- **Call Contract**: Supports explicit keyword argument binding. Safely differentiates between `AlertInfo` lists and `StatsSnapshot` instances.
- **Field Escaping**: Robustly quotes commas, double quotes (`""`), newlines, and multi-byte Unicode strings.
- **Packet Stream Format**: `id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, length, service, info`
- **Security Alerts Format**: `id, timestamp, severity, rule_name, message, src_ip, dst_ip, dst_port, protocol`
- **Statistics Section**: Appends aggregated session throughput, byte volume, and packet metrics if `stats` snapshot is supplied.

#### C. Machine-Readable JSON Export (`export_json(filepath, packets=None, alerts=None, stats=None, hosts=None)`)
- Produces fully serialized JSON with structured fields:
  - `metadata`: `application`, `version`, `exported_at`, `total_packets`, `total_alerts`, `total_hosts`.
  - `stats`: `total_packets`, `total_bytes`, `elapsed_seconds`, `packets_per_sec`, `bytes_per_sec`, `unique_hosts`, `protocol_counts`, `top_talkers`.
  - `alerts`: List of serializable alert objects.
  - `hosts`: List of discovered hosts with IP, MAC, hostname, open ports, and services.
  - `packets`: Optional list of decoded packet records.
- Gracefully handles empty or partial datasets while preserving top-level metadata schema.

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
