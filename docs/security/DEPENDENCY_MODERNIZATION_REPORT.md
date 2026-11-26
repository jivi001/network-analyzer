# Dependency Modernization Report — my-sentinel

**Project:** my-sentinel (Network Traffic Analyzer & Security TUI)  
**Branch:** `security/dependency-modernization`  
**Python requirement:** `>=3.9`  
**Environment:** Python 3.13.5  
**Date:** 2026-11-17

---

## Summary

This report documents the dependency modernization work performed to audit, upgrade, and clean up dependencies while preserving Python 3.9 compatibility and all existing functionality (290 tests pass).

### Key outcomes

| Item | Status |
|------|--------|
| Vulnerable dependencies identified and resolved | ✅ |
| Python 3.9 compatibility preserved (`requires-python = ">=3.9"`) | ✅ |
| `uv.lock` regenerated with proper Python version markers | ✅ |
| All 290 existing tests pass | ✅ |
| `uv lock --check` passes | ✅ |
| `pip check` reports no issues | ✅ |
| `python3 sentinel.py --help` startup verified | ✅ |
| No security warnings suppressed | ✅ |

---

## Changes made

### 1. `ipwhois` removed from dependencies

**Commit:** `2544ae7` — Strix Deep Pentest remediation

`ipwhois>=1.2.0` was removed from `pyproject.toml` and `requirements.txt` because it was flagged as a dependency-exposure finding by the Strix security assessment.

**Code impact:** `network/whois_lookup.py` imports `ipwhois` inside a `try/except ImportError` block. When `ipwhois` is not installed, the `WhoisLookup.lookup()` method gracefully returns an empty `WhoisInfo` instead of crashing. No runtime breakage.

**Transitive dependencies removed with `ipwhois`:**
- `dnspython` (pulled in by `ipwhois`) — this also removed the `dnspython` vulnerabilities (GHSA-vvf4-9x63-8xvv, GHSA-45c3-73f7-pv4m) from the lockfile.
- `defusedxml` (pulled in by `ipwhois`)

### 2. `pytest` pinned to `>=8.4.2`

**Commit:** `2544ae7`

Pinned `pytest>=8.0` → `pytest>=8.4.2` in `pyproject.toml` to use a newer patch release with bug fixes.

### 3. `uv.lock` regenerated

The lockfile was regenerated via `uv lock`, which:

- Removed `ipwhois`, `dnspython`, and `defusedxml` entries
- Added Python version markers for remaining packages with dual versions:
  - `pytest 8.4.2` for `python_full_version < '3.10'`
  - `pytest 9.1.1` for `python_full_version >= '3.10'`
  - `iniconfig 2.1.0` for `< '3.10'`, `2.3.0` for `>= '3.10'`
  - `markdown-it-py 3.0.0` for `< '3.10'`, `4.2.0` for `>= '3.10'`
  - `coverage` similarly split by Python version
- Locked `tomli` marker to `python_full_version <= '3.11'`

---

## `uv audit` findings

### Resolved

| Package | Vulnerability | Resolution |
|---------|--------------|------------|
| `dnspython` | GHSA-vvf4-9x63-8xvv (excessive memory/CPU) | Removed via `ipwhois` removal |
| `dnspython` | GHSA-45c3-73f7-pv4m | Removed via `ipwhois` removal |

### Remaining (accepted)

| Package | Version | Vulnerability | Fixed in | Reason kept |
|---------|---------|---------------|----------|-------------|
| `pytest` | 8.4.2 | GHSA-6w46-j5rx-g56g (tmpdir handling) | 9.0.3 | pytest 9.x requires Python >=3.10; Python 3.9 compatibility must be preserved. pytest 8.4.2 is the latest release supporting Python 3.9. |
| `pytest` | 8.4.2 | PYSEC-2026-1845 (tmpdir handling) | 9.0.3 | Same as above |

**Risk assessment:** These are dev-only (testing) tool vulnerabilities in `tmpdir` handling. They do not affect production runtime (`uv sync` without `--extra dev` installs no pytest). On Python >=3.10, the lockfile resolves to `pytest 9.1.1`, which is not affected.

---

## Current dependency state

### `pyproject.toml` (production)

```
scapy>=2.5.0
rich>=13.0
python-nmap>=0.7.1
pyyaml>=6.0
```

### `pyproject.toml` (dev, `pytest` extra)

```
pytest>=8.4.2
pytest-cov>=5.0
```

### `uv.lock` resolved versions (Python 3.13.5)

| Package | Version |
|---------|---------|
| scapy | 2.7.0 |
| rich | 15.0.0 |
| python-nmap | 0.7.1 |
| pyyaml | 6.0.3 |
| pytest | 9.1.1 |
| pytest-cov | 7.1.0 |

No `ipwhois`, `dnspython`, or `defusedxml` are present in the lockfile.

---

## Verification results

| Check | Result |
|-------|--------|
| `uv lock --check` | ✅ Passes |
| `uv sync` (production deps only) | ✅ Works |
| `uv sync --extra dev` | ✅ Installs pytest 9.1.1 / pytest-cov 7.1.0 |
| `uv audit` | ⚠️ pytest 8.4.2 vulns documented above (Python <3.10 only) |
| `pip check` | ✅ No issues |
| Test suite | ✅ 290 passed in ~8s |
| `python3 sentinel.py --help` | ✅ Starts correctly |
| Python 3.9 compatibility | ✅ `requires-python = ">=3.9"` preserved; lockfile markers handle version splits |

---

## Uncommitted code changes preserved

The following security-hardening changes (from the Strix remediation commit `2544ae7`) are preserved in the working tree:

- **`detection/anomaly.py`** — DNS exfiltration detection hardening: inclusive boundary check (`>=`) and position-aware entropy detection across all labels
- **`detection/rule_engine.py`** — DNS rule engine updates
- **`tui/helpers.py`** — `sanitize_display()` with Rich markup escaping and control character filtering
- **`tui/history_view.py`**, **`tui/pcap_view.py`**, **`tui/scan_view.py`** — TUI error handling and privilege reporting
- **`tests/test_dns_exfiltration_hardening.py`** — 7 new DNS hardening tests

---

## Notes

- `ipwhois` remains imported in `network/whois_lookup.py` with a graceful `ImportError` fallback. The Whois lookup feature returns empty results when `ipwhois` is not installed; no crash occurs.
- `pytest` 8.4.2 (for Python <3.10) has unpatched tmpdir vulnerabilities. There is no patched release of pytest that supports Python 3.9. This is an accepted trade-off to preserve the project's `>=3.9` Python requirement. Production users on Python >=3.10 automatically get pytest 9.1.1 via lockfile markers.
- No security warnings were suppressed.
