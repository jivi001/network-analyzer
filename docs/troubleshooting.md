# Troubleshooting Guide

Solutions for common installation, runtime, capture, scanning, and database issues.

## 1. Capture Issues

### Problem: `Sniffer error: No interfaces found` or `Permission denied`
- **Cause**: Npcap (Windows) or libpcap (Linux) is missing, or terminal lacks Administrator/root privileges.
- **Solution**:
  1. Windows: Install [Npcap](https://npcap.com/) in **WinPcap API-compatible mode**.
  2. PowerShell: Right-click PowerShell and select **Run as Administrator**.
  3. Linux: Execute with `sudo .venv/bin/sentinel`.

### Problem: Sniffer starts but no packets appear in table
- **Cause**: Incorrect interface selected or overly restrictive BPF filter.
- **Solution**:
  1. Press `F` in Live Capture mode and clear the filter string (press Enter).
  2. Verify active interface string in main settings menu.

---

## 2. Network Scanning Issues

### Problem: `Failed to initialize Nmap PortScanner` or `Nmap executable unavailable`
- **Cause**: Nmap is not installed or `nmap.exe` is not present in system `%PATH%`.
- **Solution**:
  1. Install Nmap from [nmap.org](https://nmap.org/download.html).
  2. Verify command prompt recognition:
     ```powershell
     nmap --version
     ```
  3. Restart PowerShell prompt after modifying system `%PATH%`.

### Problem: `Invalid target address or hostname`
- **Cause**: Target string failed `validate_target()` check (e.g. contains spaces or shell characters).
- **Solution**: Enter clean IPv4, IPv6, CIDR, or hostname strings (e.g. `192.168.1.1`, `192.168.1.0/24`, `example.com`).

---

## 3. Database Issues

### Problem: `sqlite3.OperationalError: database is locked`
- **Cause**: Another process or connection holds an active write transaction on `sentinel_data.db`.
- **Solution**:
  - `my-sentinel` enables SQLite **WAL mode** and `busy_timeout=10000ms` automatically. Ensure no secondary database viewer tool holds open locks on the file.

---

## 4. TUI Display Issues

### Problem: Terminal text overlaps or screens double-render
- **Cause**: Multiple un-coordinated `Console()` instances or output written while `Live` is running.
- **Solution**:
  - Verify that all custom TUI modules import `from utils.console import console`. All rendering must pass through the single shared `Console` object.
