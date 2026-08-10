# Frequently Asked Questions (FAQ)

## 1. How is `my-sentinel` installed on Windows?
Run `install.ps1` in PowerShell as Administrator. This creates `.venv/`, installs all dependencies (`scapy`, `rich`, `python-nmap`, `ipwhois`, `pyyaml`), installs `my-sentinel` as an editable package, and adds `sentinel` to your executable PATH.

---

## 2. Does `my-sentinel` generate synthetic packet data during live capture?
**No.** All production packet capture uses real live network traffic captured directly from the network interface using Scapy and Npcap/libpcap.

---

## 3. How does `my-sentinel` prevent memory leaks during high-speed packet capture?
`my-sentinel` enforces strict RAM bounding:
1. `scapy.sniff(store=0)` prevents Scapy from saving raw packets in RAM.
2. Packet processing queue is bounded to 5,000 packets (`queue.Queue(maxsize=5000)`). Excess packets trigger graceful drops and update the `dropped_count` metric.
3. The TUI live packet display uses a ring-buffer capped at 500 packets.
4. Raw PCAP streaming writes directly to disk asynchronously.

---

## 4. Why does Nmap require Administrator privileges?
Nmap SYN stealth scans (`-sS`), OS detection (`-O`), and UDP scanning (`-sU`) build raw IP packets directly, which requires Administrator permissions on Windows and `root` privileges on Linux. Unprivileged users can execute TCP Connect (`tcp_connect`, `-sT`) and Host Discovery (`discovery`, `-sn`) profiles.

---

## 5. How are security threat alerts deduplicated?
The signature rule engine (`RuleEngine`) tracks recent alerts using a sliding deduplication window (default: 60 seconds). Duplicate alerts with the same `(rule_id, src_ip, dst_ip)` occurring within the window are suppressed.
