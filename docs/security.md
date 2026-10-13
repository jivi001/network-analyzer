# Security Hardening & Vulnerability Mitigation

Evidence-based documentation of implemented security controls and data safety guards in `my-sentinel`.

## 1. Implemented Security Controls

### 1.1 Security Controls Matrix

| Threat / Risk Vector | Implemented Mitigation | Implementation File | Standard / CWE |
|----------------------|------------------------|---------------------|----------------|
| **Argument Injection in Scanner** | Target strings validated against IP/CIDR/hostname regex. Arguments strictly allowlisted with standalone/parameter validation; option smuggling (`-oX`, `--script`, shell metachars) rejected. Scans executed via `python-nmap` bindings without `shell=True`. | [`core/scanner.py`](../core/scanner.py) | **CWE-88** |
| **Path Traversal & Sibling Collisions** | Export file paths sanitized with `validate_export_path()` (`allow_absolute=False` by default). Resolves real paths, enforces strict directory containment (preventing sibling bypasses like `exports_evil/`), denylists system roots, and prohibits filesystem mutation before validation. | [`storage/exporter.py`](../storage/exporter.py) | **CWE-22 / CWE-23** |
| **Command Injection in BPF Filters** | BPF strings validated via `validate_bpf_filter()` to enforce strict character allowlists and syntax checks before passing to `scapy.sniff`. | [`sentinel.py`](../sentinel.py) | **CWE-78** |
| **SQL Injection** | All database queries use parameterized SQL placeholders (`?`). No raw user strings are concatenated into SQL queries. Thread-local connection pooling with WAL mode and busy timeouts. | [`storage/database.py`](../storage/database.py) | **CWE-89** |
| **Insecure Randomness in DNS** | DNS transaction IDs generated using cryptographically secure PRNG (`secrets.randbits(16)`), mitigating DNS cache poisoning and transaction spoofing. | [`traffic_lab.py`](../traffic_lab.py) | **CWE-330** |
| **Insecure Temporary File Creation** | Temporary PCAP exports use `tempfile.mkstemp` with restricted file permissions (`0o600`), explicit file descriptor closure, and guaranteed cleanup on error or exit. | [`sentinel.py`](../sentinel.py) | **CWE-377 / CWE-732** |
| **Unbounded Resource Exhaustion** | Traffic generation worker pool submissions bounded by a `threading.Semaphore(max_workers * 2)` to prevent unbounded task queuing and memory exhaustion. | [`traffic_lab.py`](../traffic_lab.py) | **CWE-400** |
| **Sniffer Shutdown Deadlocks** | Scapy sniffer loop uses bounded 500ms timeouts (`timeout=0.5, count=50`) allowing non-blocking stop flag evaluation and deterministic thread joins even on idle interfaces. | [`core/sniffer.py`](../core/sniffer.py) | **CWE-835** |
| **Unsafe YAML Loading** | Detection rules loaded using `yaml.safe_load()` to prevent arbitrary code execution during rule parsing. | [`detection/rule_engine.py`](../detection/rule_engine.py) | **CWE-502** |
| **Privacy Data Leakage** | `PrivacyFilter` provides deterministic IP masking (e.g. `192.168.1.50` -> `X.X.X.50` or `192.168.1.X`) across TUI views and exported data. | [`utils/privacy.py`](../utils/privacy.py) | **CWE-200 / CWE-359** |
| **Import Payload Exploits** | `storage/importer.py` validates schema types, non-negative packet counts, and executes imports inside atomic transactions. | [`storage/importer.py`](../storage/importer.py) | **CWE-20** |

---

### 1.2 Scanner Argument Injection Defense (CWE-88)
In [`core/scanner.py`](../core/scanner.py), Nmap arguments are checked via `validate_scan_args(custom_args)`:
- **Standalone Flags Allowlist**: Exactly restricted to `-sn`, `-sS`, `-sT`, `-sV`, `-sU`, `-O`, `-A`, `-T0` through `-T5`, `-Pn`, `-n`, `-v`, `-vv`, and `-6`.
- **Parameter Flags Allowlist**: Strictly validates options that consume values (e.g., `--top-ports <N>`, `--host-timeout <N>s`, `-p <ports>`).
- **Forbidden Argument Classes**: Rejects file output flags (`-oN`, `-oX`, `-oG`, `-oA`), script engines (`--script`, `--script-args`), input file redirects (`-iL`, `-iR`), and resume options.
- **Smuggling & Metacharacter Rejection**: Rejects any arguments containing shell operators (`;`, `&`, `|`, `` ` ``, `$`, `\n`) or merged option strings designed to evade parsing.

### 1.3 Export Path Containment & Traversal Defense (CWE-22 / CWE-23)
In [`storage/exporter.py`](../storage/exporter.py), `validate_export_path(filepath, export_dir, allow_absolute=False)` enforces:
- **Strict Containment**: Resolves `os.path.realpath` for both the export directory and the target path. Traverses ancestor directories to verify that the target's parent strictly matches the export directory, preventing sibling collisions (e.g., `exports_evil/` attempting to pass a string prefix check against `exports/`).
- **No Absolute Path Leakage**: Defaults to `allow_absolute=False`. Any absolute paths outside the configured export root are rejected unless explicit bypass is permitted by programmatic callers.
- **System Directory Denylist**: Explicitly rejects paths located in root-level or critical operating system directories (`/etc`, `/bin`, `/sbin`, `/usr`, `/var`, `/boot`, `/dev`, `C:\Windows`, `C:\Program Files`).
- **Zero Pre-Validation Mutation**: Directory creation (`os.makedirs`) is deferred until after validation successfully completes, preventing unauthorized directory creation on disk.

### 1.4 Resource Lifecycle & Concurrency Safeguards
- **Traffic Lab Task Backpressure**: [`traffic_lab.py`](../traffic_lab.py) wraps thread pool submissions in a counting semaphore. Submissions block if pending tasks exceed twice the worker count, preventing out-of-memory crashes during high-rate packet replay or flood testing.
- **Sniffer Thread Termination**: Scapy's native `sniff(stop_filter=...)` only evaluates upon incoming packet arrival. If no packets arrive on an idle interface, the thread could block indefinitely. [`core/sniffer.py`](../core/sniffer.py) executes packet capture in 500ms intervals, evaluating `self.running.is_set()` every half-second to guarantee prompt join operations on shutdown.
- **Deterministic Database Lifecycle**: [`storage/database.py`](../storage/database.py) uses thread-local SQLite storage with WAL journaling, `busy_timeout=10000ms`, `is_alive()` health checks, and a central `close_all()` hook to release database file locks cleanly during application shutdown.

---

## 2. Authorization & Network Safety Directives

- **Authorized Testing Only**: Network scanning (`NetworkScanner`) and traffic simulation (`TrafficLab`) must only be performed against systems and networks that you own or are explicitly authorized to assess.
- **Privilege Separation**: Administrator / root checks enforce required permissions for raw packet capture and OS fingerprinting without granting unnecessary system rights.
- **Zero Synthetic Artifacts in Production**: Synthetic or mock packets, fabricated alerts, and simulated scan results are strictly restricted to unit tests and never injected into production capture pipelines.

---

## 3. XML & XXE Security Policy

MY-SENTINEL establishes a strict, application-wide security policy governing XML processing and XXE mitigation:

### Policy Mandates
1. **Current Production Status**: No production XML parsing path exists within MY-SENTINEL. The application primarily consumes JSON (`importer.py`) and YAML (`yaml.safe_load`).
2. **Forbidden Parsers**: UNTRUSTED XML MUST NOT be parsed with unsafe or default XML parsers. Specifically forbidden:
   - `xml.etree.ElementTree.parse()` / `fromstring()`
   - `lxml.etree.parse()` / `fromstring()`
   - `xml.dom.minidom` / `pulldom`
   - `xml.sax`
3. **Mandatory Future Controls**: Any future feature requiring untrusted XML processing MUST:
   - Use a proven hardened parser (specifically `defusedxml`).
   - Prohibit external entity resolution (`SYSTEM` / `PUBLIC` entities).
   - Prohibit external DTD fetching and parameter entity resolution.
   - Prohibit XInclude and external network resource loading.
   - Enforce strict resource limits: maximum document size, max node count, max depth, and text length to protect against Billion Laughs and quadratic blowup bombs.
4. **Boundary Defense**:
   - `storage/importer.py` strictly accepts only `.json` files and parses via standard `json.load()` inside atomic transactions; XML files are rejected before file opening.
   - `storage/exporter.py` strictly restricts exports to `.pcap`, `.csv`, and `.json`; `.xml` requests are rejected.
   - `core/scanner.py` executes Nmap via `python-nmap` with strict target validation and allowlisted arguments, rejecting `-oX`, `-oA`, and output redirection flags. No external XML files or scan outputs are parsed by MY-SENTINEL directly.

