# Security Hardening & Vulnerability Mitigation

Evidence-based documentation of implemented security controls and data safety guards in `my-sentinel`.

## 1. Implemented Security Controls

| Threat / Risk Vector | Implemented Mitigation | Implementation File |
|----------------------|------------------------|---------------------|
| **Command Injection in Scanner** | Target strings validated against IP/CIDR/hostname regex. Arbitrary shell arguments rejected. Scans executed via `python-nmap` bindings without `os.system` or `subprocess(shell=True)`. | [`core/scanner.py`](../core/scanner.py) |
| **Command Injection in BPF Filters** | BPF strings validated via `validate_bpf_filter()` to enforce strict character allowlists and syntax checks before passing to `scapy.sniff`. | [`sentinel.py`](../sentinel.py) |
| **Path Traversal in Exports** | Export file paths sanitized with `validate_export_path()` to reject `..` and restrict exports safely. | [`storage/exporter.py`](../storage/exporter.py) |
| **SQL Injection** | All database queries use parameterized SQL placeholders (`?`). No raw user strings are concatenated into SQL queries. | [`storage/database.py`](../storage/database.py) |
| **Unsafe YAML Loading** | Detection rules loaded using `yaml.safe_load()` to prevent arbitrary code execution during rule parsing. | [`detection/rule_engine.py`](../detection/rule_engine.py) |
| **Privacy Data Leakage** | `PrivacyFilter` provides deterministic IP masking (e.g. `192.168.1.50` -> `X.X.X.50` or `192.168.1.X`) across TUI views and exported data. | [`utils/privacy.py`](../utils/privacy.py) |
| **Import Payload Exploits** | `storage/importer.py` validates schema types, non-negative packet counts, and executes imports inside atomic transactions. | [`storage/importer.py`](../storage/importer.py) |

---

## 2. Authorization & Network Safety Directives

- **Authorized Testing Only**: Network scanning (`NetworkScanner`) must only be performed against systems and networks that you own or are explicitly authorized to assess.
- **Privilege Separation**: Administrator / root checks enforce required permissions for raw packet capture and OS fingerprinting without granting unnecessary system rights.

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

