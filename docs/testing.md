# Automated Testing & Stress Validation Guide

`my-sentinel` includes a comprehensive test suite built on `unittest` and `pytest`.

## 1. Test Suite Commands

Run the full automated test suite using `pytest`:

```powershell
.venv\Scripts\python.exe -m pytest tests\ -v
```

Or using `unittest`:

```powershell
.venv\Scripts\python.exe -m unittest tests/test_audit_regressions.py tests/test_subsystem_stress.py
```

---

## 2. Test File Breakdown

| Test File | Focus & Coverage | Test Count |
|-----------|------------------|------------|
| [tests/test_audit_regressions.py](file:///d:/Programs/Security/network-analyzer/tests/test_audit_regressions.py) | Hardening regressions: BPF filter validation, target validation, SQLite persistence/recovery, path traversal, rule engine deduplication, pipeline exception isolation. | 14 |
| [tests/test_subsystem_stress.py](file:///d:/Programs/Security/network-analyzer/tests/test_subsystem_stress.py) | Subsystem stress & concurrency: AlertManager multithreading, AnomalyDetector bounds, Sniffer state machine, Rich markup escaping, single Console sharing, Nmap profile allowlist & model normalization. | 15 |

**Total Suite Coverage: 29 Passing Unit & Subsystem Tests.**

---

## 3. Key Test Categories

### A. Security & Path Traversal Rejection
- `test_exporter_path_traversal_rejection`: Confirms paths containing `../` or `..\` are sanitized to prevent writing files outside `export_directory`.
- `test_importer_strict_validation`: Confirms invalid JSON schemas or negative packet counts trigger explicit `ValueError` rejections.

### B. Target & BPF Input Validation
- `test_bpf_filter_validation`: Validates BPF syntax checking and rejection of invalid string commands.
- `test_scanner_target_validation`: Confirms IP, CIDR, hostname validation and rejection of leading hyphens or shell injection attempts.

### C. Nmap Scan Profile Allowlist & Model Normalization
- `test_nmap_scan_profiles_allowlist_and_arguments`: Validates all 12 scan profiles enforce `--host-timeout`.
- `test_nmap_invalid_scan_profile_rejection`: Confirms unallowlisted profile strings raise `ValueError`.
- `test_nmap_mocked_profile_scanning_and_normalization`: Mocks Nmap scanner and verifies `ScanResult` / `HostInfo` model structure.

### D. Single Console Ownership & Render Idempotency
- `test_single_console_instance_sharing`: Asserts all TUI modules reference the exact same `utils.console.console` object.
- `test_tui_rendering_start_stop_idempotency`: Verifies multiple `Live.start()` / `Live.stop()` calls execute safely without duplicating render loops.
