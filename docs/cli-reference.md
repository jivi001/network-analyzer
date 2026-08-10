# CLI Command Reference

`my-sentinel` can be launched interactively or executed in automated command-line mode.

## 1. Syntax

```powershell
sentinel [OPTIONS]
```

Or using the Python executable directly:

```powershell
.venv\Scripts\python.exe sentinel.py [OPTIONS]
```

---

## 2. Command-Line Arguments

| Flag | Argument | Description | Default |
|------|----------|-------------|---------|
| `--capture` | None | Bypasses main menu and launches Live Capture mode directly. | False |
| `--scan` | `<TARGET>` | Scans specified target (IP, CIDR, or hostname) directly from CLI. | None |
| `--profile` / `--scan-profile` | `<PROFILE>` | Sets Nmap scan profile for `--scan` mode (e.g. `service`, `discovery`, `comprehensive`). | `"top_ports"` |
| `--pcap` | `<FILEPATH>` | Analyzes specified offline `.pcap`/`.pcapng` file directly from CLI. | None |
| `--mask` | None | Enables IP address privacy masking across TUI and exports. | False |
| `--no-admin-check` | None | Bypasses startup Administrator privilege check (some features may fail). | False |
| `--config` | `<FILEPATH>` | Overrides default `config.yaml` path. | `"config.yaml"` |
| `--db` | `<FILEPATH>` | Overrides default SQLite database path. | `"sentinel_data.db"` |
| `--version` | None | Displays application version (`my-sentinel v1.0.0`) and exits. | False |
| `-h`, `--help` | None | Displays help message and CLI argument summary. | False |

---

## 3. Example Execution Commands

### Direct Live Capture with Privacy Masking

```powershell
sentinel --capture --mask
```

### Direct Network Scan using Service Detection Profile

```powershell
sentinel --scan 192.168.1.0/24 --profile service
```

### Direct PCAP File Forensic Analysis

```powershell
sentinel --pcap exports\capture_20260810_183000.pcap
```

### Custom Database and Configuration Files

```powershell
sentinel --config custom_config.yaml --db /var/log/sentinel_audit.db
```
