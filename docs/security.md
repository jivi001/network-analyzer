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
