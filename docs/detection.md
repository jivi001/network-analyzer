# Threat Detection System & Rule Engine

## 1. Subsystem Architecture

`my-sentinel` includes a multi-vector detection engine operating in real time across captured packets:

```text
                           PacketInfo Dataclass
                                    │
                                    ▼
                      PacketDetectionPipeline.evaluate()
                                    │
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
      RuleEngine             AnomalyDetector             ArpMonitor
  (Signature Rules)      (Behavioral Analysis)      (MAC Binding State)
```

---

## 2. Signature-Based Detection (`detection/rule_engine.py`)

`RuleEngine` loads YAML signature rules from the `rules/` directory.

### Signature Rule Structure (`rules/default_rules.yaml`)

```yaml
rules:
  - id: "RULE-001"
    name: "Cleartext Telnet Traffic"
    severity: "HIGH"
    condition:
      protocol: "TCP"
      dst_port: 23
    message: "Cleartext Telnet connection attempt detected"

  - id: "RULE-002"
    name: "Cleartext FTP Authentication"
    severity: "MEDIUM"
    condition:
      protocol: "TCP"
      dst_port: 21
    message: "Cleartext FTP traffic detected"

  - id: "RULE-003"
    name: "TCP Null Scan"
    severity: "HIGH"
    condition:
      protocol: "TCP"
      flags_exact: ""
    message: "TCP packet with no flags set (Null scan)"

  - id: "RULE-004"
    name: "TCP Xmas Scan"
    severity: "HIGH"
    condition:
      protocol: "TCP"
      flags_contains: ["FIN", "PSH", "URG"]
    message: "TCP Xmas scan detected (FIN+PSH+URG set)"

  - id: "RULE-005"
    name: "SYN-FIN Scan"
    severity: "HIGH"
    condition:
      protocol: "TCP"
      flags_contains: ["SYN", "FIN"]
    message: "TCP packet with both SYN and FIN set"
```

### Alert Deduplication Window

`RuleEngine` tracks rule alerts in a sliding window to prevent flooding. If an alert with key `(rule_id, src_ip, dst_ip)` fired within `dedup_window` seconds (default: 60s), the duplicate alert is suppressed.

---

## 3. Behavioral Anomaly Detection (`detection/anomaly.py`)

`AnomalyDetector` detects anomalous traffic patterns using sliding windows:

### A. Shannon Entropy DNS Exfiltration Analysis
- Measures domain entropy using $H(X) = -\sum P(x_i) \log_2 P(x_i)$.
- Ignores subdomains shorter than `dns_min_subdomain_length` (default: 20 characters).
- If calculated entropy exceeds `dns_entropy_threshold` (default: 3.5 bits/char), fires a `CRITICAL` severity `DNS Exfiltration Suspicion` alert.

### B. Port Scan Detection
- Tracks unique destination ports contacted by each source IP within a sliding 10-second window.
- If a source IP targets $\ge 15$ distinct ports within 10 seconds, fires a `HIGH` severity `Port Scan Detected` alert.

---

## 4. Layer 2 ARP Security (`detection/arp_monitor.py`)

`ArpMonitor` maintains a thread-safe state table of IP-to-MAC address bindings:
- **First-Seen Learning**: When an IP address is observed for the first time, its MAC address is bound without alerting.
- **MAC Alteration / Spoofing**: If an ARP reply or packet announces a different MAC address for an existing IP binding, fires a `CRITICAL` severity `ARP Spoofing / MAC Mismatch` alert specifying `old_mac` and `new_mac`.

---

## 5. Alert Storage & Management (`detection/alerts.py`)

`AlertManager` stores alerts in a ring-buffer in memory (`max_alerts`, default: 100) and saves all alerts to the SQLite database via `Database.save_alert(alert)`.
