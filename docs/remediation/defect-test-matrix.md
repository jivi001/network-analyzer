# Master Defect-to-Test Mapping Matrix

**Project:** `jivi001/network-analyzer` (`my-sentinel`)  
**Baseline Anchor:** Commit `66c7b254ac52c14110406c623ea79447ca2f0cd7`  
**Current Phase:** Phase 2 (Security Boundary Hardening)  

---

## Matrix Legend
- **Baseline Status:**
  - `CONFIRMED_FAILING`: Defect directly verified by a failing test in the baseline pytest run.
  - `CONFIRMED_STATIC`: Defect verified by compiler/linter/type-checker (e.g. MyPy, Bandit, AST analysis) during baseline audit.
  - `CONFIRMED_ARCH`: Architectural / concurrency defect verified through code inspection.
- **Verification Status:**
  - `VERIFIED_RESOLVED`: Minimal fix implemented and verified by green automated regression tests.
  - `UNRESOLVED`: Preserved as out-of-scope for Phase 1; scheduled for subsequent remediation phases.

---

## Defect-to-Test Matrix

| Finding ID | Affected File & Location | Root Cause | Minimal Fix Applied | Regression Test & Verification Command | Baseline Status | Remediation Phase | Verification Status | Remaining Limitations |
|---|---|---|---|---|---|---|---|---|
| **DEF-001** | `sentinel.py:102-108` | `os.makedirs(PROJECT_ROOT / "logs")` executes on import. | Scheduled for Phase 2. | TBD | `CONFIRMED_STATIC` | Phase 2 | `UNRESOLVED` | Out-of-scope for Phase 1. |
| **DEF-002** | `sentinel.py:299` | `pending_alerts: List[AlertInfo]` references unimported `AlertInfo`. | Scheduled for Phase 2. | TBD | `CONFIRMED_STATIC` | Phase 2 | `UNRESOLVED` | Out-of-scope for Phase 1. |
| **DEF-003** | `sentinel.py:624`, `storage/exporter.py:200-206`, `tests/test_audit_regressions.py:98` | `snapshot` (`StatsSnapshot`) passed positionally as 3rd parameter to `export_csv(filepath, packets, alerts, stats)`, binding to `alerts`. If `packets` was empty, iterating `alerts` crashed with `TypeError: 'StatsSnapshot' object is not iterable`. Audit confirmed positional binding was an undocumented caller mistake. | 1. Switched `sentinel.py:624` to explicit keyword arguments `packets=list(packet_buffer), stats=snapshot`.<br>2. Switched `sentinel.py:530` and `631` to explicit keyword arguments for `export_json`.<br>3. Updated legacy test caller in `tests/test_audit_regressions.py:98` to `packets=[packet], stats=stats.get_snapshot()`.<br>4. Removed implicit argument-repair guard in `storage/exporter.py:export_csv`, enforcing type contract.<br>5. Replaced `if not wrpcap:` with `if wrpcap is None:`. | `tests/test_export_correctness.py::TestExportCorrectnessPhase1::test_export_csv_packets_with_keyword_contract`<br>`tests/test_export_correctness.py::TestExportCorrectnessPhase1::test_export_csv_positional_stats_snapshot_type_enforcement`<br>**Cmd:** `pytest tests/test_export_correctness.py -v` (8 passed) | `CONFIRMED_STATIC` | Phase 1 | `VERIFIED_RESOLVED` | None. All supported formats (CSV, JSON, PCAP) verified and fully backward compatible. |
| **DEF-004** | `traffic_lab.py:66` | Pseudo-random PRNG for DNS TID (CWE-330). | Scheduled for Phase 2. | TBD | `CONFIRMED_STATIC` | Phase 2 | `UNRESOLVED` | Out-of-scope for Phase 1. |
| **DEF-005** | `sentinel.py:306-308` | Insecure temp PCAP file permissions (CWE-377/732). | Scheduled for Phase 2. | TBD | `CONFIRMED_STATIC` | Phase 2 | `UNRESOLVED` | Out-of-scope for Phase 1. |
| **DEF-006** | `core/scanner.py:64-94` | Permissive prefix-based flag matching (`token.startswith(p)`) permitted dangerous option lookalikes (e.g., `-Append-output`, `-Apple`, `-packet-trace`, `-privileged`, `-666`, `-T2evil`) and unvalidated values (CWE-88). | 1. Partitioned options into exact-match `STANDALONE_FLAGS` and parameter-consuming `OPTION_FLAGS`.<br>2. Implemented strict validators for ports (`_validate_port_spec`), ranges, and option parameters (`_validate_option_value`).<br>3. Blocked mutually exclusive options (`-p` vs `--top-ports`), incompatible scan types, lookalikes, and orphan tokens. | `tests/test_security_boundary_phase2.py::TestNmapArgumentValidationPhase2`<br>**Cmd:** `pytest tests/test_security_boundary_phase2.py -v` (14 passed) | `CONFIRMED_STATIC` | Phase 2 | `VERIFIED_RESOLVED` | None. Backward-compatibility alias `_SAFE_ARG_PREFIXES` preserved. |
| **DEF-006b** | `storage/exporter.py:25-70` | String-prefix path containment (`target_abs.startswith(base_abs)`) allowed sibling directory prefix collisions (`exports_evil` matching `exports`), insufficient system directory validation on absolute paths, and pre-validation directory creation (CWE-22 / CWE-23). | 1. Replaced string check with path-aware containment (`Path.is_relative_to()`).<br>2. Added explicit sibling-collision rejection (`real_parent.parent == base_dir.parent`).<br>3. Prohibited root `/` and system directories (POSIX and Windows) using `PureWindowsPath` normalization.<br>4. Verified failures occur before directory creation. | `tests/test_security_boundary_phase2.py::TestExportPathContainmentPhase2`<br>**Cmd:** `pytest tests/test_security_boundary_phase2.py -v` (14 passed) | `CONFIRMED_STATIC` | Phase 2 | `VERIFIED_RESOLVED` | None. Safe absolute paths preserved for test suites. |
| **DEF-007** | `utils/path_helpers.py:33-46` | Backslash path parsing failure on POSIX. | Scheduled for Phase 3. | TBD | `CONFIRMED_FAILING` | Phase 3 | `UNRESOLVED` | Out-of-scope for Phase 2. |
| **DEF-008** | `core/stats.py:42-45` | Memory sampling fallback logic mismatch. | Scheduled for Phase 3. | TBD | `CONFIRMED_FAILING` | Phase 3 | `UNRESOLVED` | Out-of-scope for Phase 2. |
| **DEF-009** | `tests/test_coverage_privileges_and_env.py:24` | `ctypes.windll` mock fails on POSIX. | Scheduled for Phase 3. | TBD | `CONFIRMED_FAILING` | Phase 3 | `UNRESOLVED` | Out-of-scope for Phase 2. |
| **DEF-010** | `tests/test_e2e_comprehensive_validation.py:191` | Unmocked live sniffer requires root. | Scheduled for Phase 3. | TBD | `CONFIRMED_FAILING` | Phase 3 | `UNRESOLVED` | Out-of-scope for Phase 2. |
| **DEF-011** | `core/sniffer.py:84-90` | Sniffer thread blocks on stop when network is quiet. | Scheduled for Phase 3. | TBD | `CONFIRMED_ARCH` | Phase 3 | `UNRESOLVED` | Out-of-scope for Phase 2. |
| **DEF-012** | `storage/database.py:28-40` | Thread-local connections leak in `_all_connections`. | Scheduled for Phase 3. | TBD | `CONFIRMED_ARCH` | Phase 3 | `UNRESOLVED` | Out-of-scope for Phase 2. |
| **DEF-013** | `traffic_lab.py:162-166` | Unbounded queue in ThreadPoolExecutor hangs on exit. | Scheduled for Phase 3. | TBD | `CONFIRMED_ARCH` | Phase 3 | `UNRESOLVED` | Out-of-scope for Phase 2. |

