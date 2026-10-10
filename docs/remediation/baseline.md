# Baseline Establishment & Remediation Readiness Report (Phase 0)

**Document:** Baseline State & Environment Assessment  
**Project:** `jivi001/network-analyzer` (`my-sentinel`)  
**Capture Timestamp:** 2026-10-10T16:15:40+05:30  
**Phase:** Phase 0 (Baseline Establishment)  
**Status:** Complete — Ready for Phase 1  

---

## 1. Repository Identity & Provenance

| Property | Value |
|---|---|
| **Remote Repository URL** | `https://github.com/jivi001/network-analyzer.git` |
| **Local Repository Path** | `/home/exu0/cybersecurity/Programs/network-analyzer` |
| **Current Git Branch** | `main` |
| **Tracking Upstream** | `origin/main` (Synchronized, up to date) |
| **Full HEAD Commit SHA** | `66c7b254ac52c14110406c623ea79447ca2f0cd7` |
| **Latest Commit Summary** | `harden XML handling and synchronize build configuration` |
| **Commit Author** | `jivi001 <jiviteshgd28@gmail.com>` |
| **Commit Date** | `Sat Sep 12 15:23:15 2026 +0530` |

---

## 2. Working-Tree Safety & Git State

Non-destructive Git status check before Phase 0 artifacts:

```text
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

- **Staged Changes:** None.
- **Unstaged Changes:** None.
- **Untracked Files:** None (prior to Phase 0 documentation generation).
- **Existing Remediation Artifacts:** None found in repository prior to Phase 0.

### Branch Decision
- **Decision:** Maintained current branch (`main`) for baseline establishment.
- **Rationale:** The working tree is clean. To strictly prevent premature branch divergence before remediation begins, no temporary branches were created. A dedicated remediation branch (e.g. `remediation/phase-1-fixes`) will be branched cleanly from `66c7b254ac52c14110406c623ea79447ca2f0cd7` at the start of Phase 1.

---

## 3. Environment & Tooling Specifications

| Component | Specification |
|---|---|
| **Host Operating System** | Linux (Parrot OS 7.1.13-1parrot1) |
| **Kernel & Architecture** | `7.1.13+parrot7-amd64 #1 SMP PREEMPT_DYNAMIC` / `x86_64` |
| **Git Version** | `git version 2.47.3` |
| **System Python** | `/usr/bin/python3` (Python 3.13.5) |
| **Test Runner Environment** | `/tmp/sentinel-venv/bin/python3` (Python 3.13.5) |
| **Test Framework** | `pytest 9.1.1` (`pluggy 1.6.0`, `cov 7.1.0`, `platformdirs 4.12.4`, `anyio 4.15.1`) |
| **Dependency Manifests** | `pyproject.toml` (653 B), `requirements.txt` (70 B), `uv.lock` (128,870 B) |

### Environmental Constraints & Limitations
1. **System Python Isolation:** The host `/usr/bin/python3` does not include `pytest` or project dependencies globally. Tests were executed via an isolated, temporary virtual environment in `/tmp/sentinel-venv` without modifying the project's working tree or files.
2. **Read-Only / Container Sandbox Constraints:** When executed under a strict read-only filesystem sandbox:
   - Module import side effect at `sentinel.py:102` (`os.makedirs(..., "logs")`) fails if `logs/` does not exist.
   - Interactive database tests fail with `sqlite3.OperationalError: unable to open database file` if write access to `./sentinel_data.db` is denied.
3. **Privilege Constraints:** Live raw packet capture requires root/UID 0 permissions. Tests that invoke live capture without mocking Scapy require elevated privileges or appropriate socket mocking.

---

## 4. Test Suite Baseline Execution

- **Exact Test Command:**
  ```bash
  PYTHONPATH=. /tmp/sentinel-venv/bin/pytest tests/ -v
  ```
- **Execution Start:** 2026-10-10T16:15:34+05:30
- **Execution Complete:** 2026-10-10T16:15:40+05:30
- **Exit Code:** `1` (Failures present)
- **Total Tests Collected:** 254 across 31 test files
- **Results:**
  - **Passed:** 250
  - **Failed:** 4
  - **Skipped:** 0
  - **Errored:** 0
  - **Total Duration:** 6.20 seconds
- **Raw Evidence Log:** Saved at `docs/remediation/evidence/phase-0-pytest.log`

---

## 5. Detailed Test Failure Triage

The 4 baseline test failures represent genuine pre-existing defects and test portability issues, not environment corruption:

### 1. `tests/test_coverage_privileges_and_env.py::TestPrivilegesAndEnvironment::test_check_privileges_windows_admin_and_non_admin`
- **Failure:** `AttributeError: module 'ctypes' has no attribute 'windll'`
- **Location:** `tests/test_coverage_privileges_and_env.py:24`
- **Root Cause:** Test attempts to patch `"ctypes.windll.shell32.IsUserAnAdmin"` on a Linux host. On POSIX platforms, `ctypes` does not define `windll`, causing `unittest.mock.patch` to raise an `AttributeError` during target resolution.
- **Classification:** Test portability defect (flawed platform mock).

### 2. `tests/test_coverage_stats_advanced.py::TestStatsAggregatorAdvanced::test_sample_process_memory_fallbacks`
- **Failure:** `AssertionError: assert 122.33203125 == 0.0`
- **Location:** `tests/test_coverage_stats_advanced.py:43`
- **Root Cause:** In `core/stats.py:_sample_process_memory_mb()`, lines 42–45:
  ```python
  else:
      import resource
      usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
      return (usage / 1024.0) if sys.platform == "darwin" else (usage / 1024.0)
  ```
  When the test patches `sys.platform = "unsupported_os"`, the `else` branch still successfully imports the POSIX `resource` module and returns actual memory usage instead of hitting an exception or returning `0.0`.
- **Classification:** Application logic & test expectation mismatch.

### 3. `tests/test_e2e_comprehensive_validation.py::CompleteEndToEndValidationTests::test_sniffer_repeated_start_stop_50_cycles`
- **Failure:** `AssertionError: False is not true`
- **Diagnostic Log:** `ERROR core.sniffer:sniffer.py:93 Sniffer error: [Errno 1] Operation not permitted`
- **Location:** `tests/test_e2e_comprehensive_validation.py:191`
- **Root Cause:** Test runs real Scapy sniffer cycles without administrative privileges (root/UID 0) and without mocking `scapy.sniff`. The OS socket creation fails with `EPERM` (Operation not permitted).
- **Classification:** Integration test un-isolated from system privileges.

### 4. `tests/test_pcap_path_validation_and_ux.py::TestPathHelpers::test_resolve_pcap_path`
- **Failure:** `AssertionError: assert 'exports\\test1.pcap' == 'test1.pcap'`
- **Location:** `tests/test_pcap_path_validation_and_ux.py:44`
- **Root Cause:** Test verifies Windows backslash path `"exports\\test1.pcap"`. On POSIX systems, backslash `\` is not a directory separator; `Path("exports\\test1.pcap").name` evaluates to `"exports\\test1.pcap"`.
- **Classification:** Application cross-platform path normalization defect.

---

## 6. Files Created During Phase 0

All Phase 0 artifacts were placed strictly in dedicated documentation locations without modifying application code or tests:

1. `docs/remediation/baseline.md` — This evidence-based repository baseline report.
2. `docs/remediation/evidence/phase-0-pytest.log` — Verifiable, unmodified output of the baseline pytest run.
3. `docs/remediation/defect-test-matrix.md` — Master defect-to-test mapping matrix for Phase 1 remediation.

---

## 7. Readiness Assessment for Phase 1

### Verdict: **READY FOR PHASE 1**

**Evidence-Based Justification:**
1. **Baseline Anchored:** Commit `66c7b254ac52c14110406c623ea79447ca2f0cd7` is clean, tracked, and verified.
2. **Reproducible Test Baseline:** Exact test command, environment, and exit code (`1`) are documented with all 4 failures identified and categorized.
3. **No Uncommitted User Changes:** No unstaged or untracked changes exist in the application source tree.
4. **Scope Integrity Preserved:** Zero application files, tests, build configurations, or dependencies were altered during Phase 0.
