# Quickstart Guide

Get up and running with `my-sentinel` in 3 minutes.

## 1. Launch `my-sentinel`

Open PowerShell as Administrator and run:

```powershell
sentinel
```

You will see the main ASCII banner and menu:

```text
  +----------------------------------------------+
  |              my-sentinel v1.0.0              |
  |      Network Traffic Analyzer & Scanner      |
  +----------------------------------------------+

  [1]  Live Capture
  [2]  Network Scan
  [3]  Analyze PCAP File
  [4]  View History
  [5]  Settings
  [Q]  Exit
```

---

## 2. Start Live Traffic Capture

1. Select option **`[1]`** from the main menu.
2. Select your network interface or press Enter to auto-detect.
3. Enter a BPF filter (e.g. `tcp port 80 or tcp port 443`) or press Enter to capture all traffic.
4. Watch the real-time TUI dashboard stream packets, calculate throughput, and display security alerts.

### Interactive Capture Controls

- **`P`**: Pause / Resume live capture rendering.
- **`F`**: Apply a new BPF capture filter dynamically.
- **`E`**: Export captured packets to CSV, JSON, or PCAP format.
- **`Q`**: Stop capture, save session, flush PCAP, and return to main menu.

---

## 3. Run a Target Network Scan

1. Select option **`[2]`** from the main menu.
2. Enter a target IP or subnet (e.g. `192.168.1.1` or `192.168.1.0/24`).
3. Select scan profile **`[3] TCP Top Ports`** or **`[4] Service Detection`**.
4. View host details, operating system guesses, and open services in the Rich results table.

---

## 4. Run Automated Unit Tests

Verify subsystem health:

```powershell
python -m pytest tests\ -v
```
