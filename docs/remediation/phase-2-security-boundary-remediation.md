# Phase 2 — Security Boundary Hardening Remediation Report

**Project:** `jivi001/network-analyzer` (`my-sentinel`)  
**Baseline Anchor:** Commit `66c7b254ac52c14110406c623ea79447ca2f0cd7`  
**Phase:** Phase 2 (Security Boundary Hardening)  
**Date:** 2026-10-10  
**Branch:** `remediation/phase-1-export-correctness`  

---

## 1. Executive Summary

Phase 2 focused strictly on hardening external security boundaries across two defined workstreams:
1. **Workstream A — Nmap Argument Validation (`DEF-006`):** Replaced permissive prefix-based option matching with strict exact allowlisting, robust option value parsing (ports, ranges, numbers, timeouts), mutual exclusivity checks, lookalike rejection, and orphan argument rejection.
2. **Workstream B — Export Path Containment (`DEF-006b`):** Replaced insecure string-prefix containment checking with path-aware validation (`Path.resolve().is_relative_to()`), eliminated sibling-directory prefix collisions (`exports_evil`), added cross-platform system directory prohibitions (POSIX and Windows via `PureWindowsPath`), and ensured failures occur prior to directory creation.

All 14 newly authored regression tests passed. Full repository testing verified 272 passing tests with exactly the 4 baseline failures preserved and zero regressions.

---

## 2. Workstream A — Nmap Argument Validation

### 2.1 Problem & Vulnerability Analysis (DEF-006 / CWE-88)
In `core/scanner.py`, custom Nmap arguments were validated by checking whether each token started with any prefix in `_SAFE_ARG_PREFIXES`:
```python
if not any(token.startswith(p) for p in self._SAFE_ARG_PREFIXES):
    raise ValueError(...)
```
Because `_SAFE_ARG_PREFIXES` included single-character flags like `-A`, `-O`, `-p`, `-6`, and compound flags like `-T2`:
- Any flag starting with `-A` passed (e.g. `-Append-output`, `-Apple`).
- Any flag starting with `-p` passed (e.g. `-packet-trace`, `-privileged`).
- Any flag starting with `-6` passed (e.g. `-666`, `-6evil`).
- Any flag starting with `-T2` passed (e.g. `-T2evil`).
- Non-flag tokens (such as `192.168.1.1` or arbitrary words) were bypassed without validation because the loop only checked tokens beginning with `-`.
- Values passed to option flags (such as `--top-ports 0`, `--top-ports abc`, `-p 80;whoami`) were unvalidated.
- Incompatible combinations (e.g., specifying both `-p` and `--top-ports`, or combining ping discovery `-sn` with port scans) were not rejected.

### 2.2 Applied Remediation
In `core/scanner.py`:
1. **Partitioned Option Sets:**
   - `STANDALONE_FLAGS`: Flags that require an exact string match and never consume parameters (`-sS`, `-sT`, `-sU`, `-sV`, `-sP`, `-sn`, `-sA`, `-sF`, `-sN`, `-sX`, `-O`, `-A`, `-6`, `-T0`–`-T5`, `-Pn`, `--open`, `-v`, `-vv`, `--osscan-limit`, `--osscan-guess`).
   - `OPTION_FLAGS`: Flags requiring a validated parameter (`--top-ports`, `--host-timeout`, `--max-retries`, `--min-rate`, `--max-rate`, `--version-intensity`, `-p`).
   - `_SAFE_ARG_PREFIXES`: Retained as `STANDALONE_FLAGS | OPTION_FLAGS` for backward compatibility.
2. **Dedicated Value Validators:**
   - `_validate_port_spec`: Strictly validates ports, port ranges (`p1-p2`), open-ended ranges (`p-`, `-p`), protocol qualifiers (`T:80,U:53`), and all-ports shorthand (`-`). Rejects letters not part of protocol prefixes, negative ports, ports > 65535, inverted ranges, and shell metacharacters.
   - `_validate_option_value`: Validates numeric ranges for `--top-ports` (1–65535), duration format for `--host-timeout` (`^\d+(ms|[smh])?$`), `--max-retries` (0–100), rates (positive integers), and `--version-intensity` (0–9).
3. **Token Parser & Combination Rules:**
   - Supports both whitespace-separated tokens (`--top-ports 1000`, `-p 80,443`) and assignment tokens (`--top-ports=1000`).
   - Supports attached `-p` flags (`-p80`, `-p1-1000`, `-p-`) while validating the remainder to prevent lookalikes like `-packet-trace` or `-privileged`.
   - Rejects orphan non-flag arguments (preventing target smuggling via `arguments`).
   - Rejects mutually exclusive combinations: `-p` with `--top-ports`, multiple TCP scan types simultaneously, and ping sweeps (`-sn`) with port scanning.

---

## 3. Workstream B — Export Path Containment

### 3.1 Problem & Vulnerability Analysis (DEF-006b / CWE-22 / CWE-23)
In `storage/exporter.py`:
1. **String-Prefix Containment Bypass:** Path containment was checked using `target_abs.startswith(base_abs)`. If `base_abs` was `/home/user/exports`, a target in a sibling directory `/home/user/exports_evil/loot.csv` satisfied `startswith()` and bypassed containment.
2. **Incomplete System Directory Denylist:** Absolute paths were only checked against a hardcoded list of three paths: `("/etc/passwd", "C:\\Windows\\system32", "/")`. Other sensitive paths (`/etc/shadow`, `/bin/sh`, `/root/`, `C:\evil.csv`, `C:\Windows\notepad.exe`) were unblocked.
3. **Platform Path Semantics:** On POSIX, Windows-style backslashes were not recognized as path separators by `Path` or `os.path`, bypassing component inspection.
4. **Pre-Validation Directory Creation:** `self.ensure_export_dir(export_dir)` was invoked prior to validating the target path, potentially creating unauthorized directory structures on failure.

### 3.2 Applied Remediation
In `storage/exporter.py`:
1. **Path-Aware Containment (`Path.is_relative_to`):**
   - Relative export targets are joined to `export_dir` and canonicalized with `Path.resolve()`.
   - Containment is verified using `real_target.is_relative_to(base_dir_path)`.
2. **Explicit Sibling Directory Collision Guard:**
   - Detects sibling directories via `real_target.parent.parent == base_dir_path.parent and real_target.parent.name.startswith(base_dir_path.name)`.
3. **Comprehensive Prohibited Directories:**
   - Prohibits POSIX roots and sensitive trees (`/`, `/etc`, `/bin`, `/sbin`, `/usr`, `/boot`, `/dev`, `/proc`, `/sys`, `/root`, `/var/run`, `/lib`, `/lib64`, `/lost+found`).
   - Prohibits Windows system roots and system directories via `PureWindowsPath` (`windows`, `system32`, `program files`, drive roots `C:\`).
4. **Absolute Path Policy:**
   - `allow_absolute` parameter: when `False`, strictly requires containment within `export_dir`. When `True` (default for backward compatibility with temporary directory fixtures in test suites), safe temporary paths are allowed while system directories and sibling collisions remain blocked.
5. **Symlink Escape Protection:**
   - Resolves target parent directories through symlinks (`target_path.parent.resolve()`), detecting and blocking symlinks pointing outside the permitted export boundary.
6. **Pre-Write Failure Isolation:**
   - Directory creation via `ensure_export_dir()` is deferred until all containment and format checks have passed.

---

## 4. Test Verification & Evidence

### 4.1 Phase 2 Focused Test Suite
Executed: `PYTHONPATH=. /tmp/sentinel-venv/bin/pytest tests/test_security_boundary_phase2.py -v`
```
tests/test_security_boundary_phase2.py::TestNmapArgumentValidationPhase2::test_allowed_option_flags_and_values PASSED [  7%]
tests/test_security_boundary_phase2.py::TestNmapArgumentValidationPhase2::test_allowed_standalone_flags PASSED [ 14%]
tests/test_security_boundary_phase2.py::TestNmapArgumentValidationPhase2::test_rejects_dangerous_and_unknown_flags PASSED [ 21%]
tests/test_security_boundary_phase2.py::TestNmapArgumentValidationPhase2::test_rejects_incompatible_option_combinations PASSED [ 28%]
tests/test_security_boundary_phase2.py::TestNmapArgumentValidationPhase2::test_rejects_malformed_option_values PASSED [ 35%]
tests/test_security_boundary_phase2.py::TestNmapArgumentValidationPhase2::test_rejects_orphan_non_flag_tokens PASSED [ 42%]
tests/test_security_boundary_phase2.py::TestNmapArgumentValidationPhase2::test_rejects_prefix_lookalikes PASSED [ 50%]
tests/test_security_boundary_phase2.py::TestExportPathContainmentPhase2::test_absolute_path_policy PASSED [ 57%]
tests/test_security_boundary_phase2.py::TestExportPathContainmentPhase2::test_failures_occur_before_writing_or_directory_creation PASSED [ 64%]
tests/test_security_boundary_phase2.py::TestExportPathContainmentPhase2::test_prohibited_system_directories_rejected PASSED [ 71%]
tests/test_security_boundary_phase2.py::TestExportPathContainmentPhase2::test_sibling_directory_prefix_collision_prevention PASSED [ 78%]
tests/test_security_boundary_phase2.py::TestExportPathContainmentPhase2::test_symlink_traversal_escape_rejected PASSED [ 85%]
tests/test_security_boundary_phase2.py::TestExportPathContainmentPhase2::test_traversal_sequences_rejected PASSED [ 92%]
tests/test_security_boundary_phase2.py::TestExportPathContainmentPhase2::test_valid_relative_paths_contained_in_export_dir PASSED [100%]

============================== 14 passed in 0.70s ==============================
```

### 4.2 Full Repository Test Suite
Executed: `PYTHONPATH=. /tmp/sentinel-venv/bin/pytest`
```
=========================== short test summary info ============================
FAILED tests/test_coverage_privileges_and_env.py::TestPrivilegesAndEnvironment::test_check_privileges_windows_admin_and_non_admin
FAILED tests/test_coverage_stats_advanced.py::TestStatsAggregatorAdvanced::test_sample_process_memory_fallbacks
FAILED tests/test_e2e_comprehensive_validation.py::CompleteEndToEndValidationTests::test_sniffer_repeated_start_stop_50_cycles
FAILED tests/test_pcap_path_validation_and_ux.py::TestPathHelpers::test_resolve_pcap_path
======================== 4 failed, 272 passed in 7.03s =========================
```

### 4.3 Test Count Progression
| Milestone | Total Collected | Passed | Failed | Delta / Notes |
|---|---|---|---|---|
| **Phase 0 Baseline** | 254 | 250 | 4 | Initial commit snapshot |
| **Phase 1 Complete** | 262 | 258 | 4 | +8 export correctness tests |
| **Phase 2 Complete** | 276 | 272 | 4 | +14 security boundary tests |

The four baseline failures remain identical and isolated:
1. `test_check_privileges_windows_admin_and_non_admin` (`ctypes.windll` mock on POSIX)
2. `test_sample_process_memory_fallbacks` (memory fallback logic mismatch on Linux)
3. `test_sniffer_repeated_start_stop_50_cycles` (unmocked sniffer requires root)
4. `test_resolve_pcap_path` (backslash relative path resolution on POSIX)

---

## 5. Files Changed in Phase 2
- `core/scanner.py`: Hardened argument validation, option allowlist, value checkers, port specs.
- `storage/exporter.py`: Path-aware containment, sibling collision checks, system directory denylist.
- `docs/remediation/defect-test-matrix.md`: Updated with DEF-006 and DEF-006b resolution status.
- `tests/test_security_boundary_phase2.py`: New regression test suite (14 tests).
- `docs/remediation/phase-2-security-boundary-remediation.md`: This report.
- `graphify-out/`: Knowledge graph updated via `graphify update .`.
