# Developer Debugging Guide

Techniques and tools for debugging `my-sentinel` runtime behavior, background threads, and detection rules.

## 1. Enabling Debug Logging

`my-sentinel` uses Python's standard `logging` module (`logger = logging.getLogger(__name__)`).

To enable verbose debug logs to stdout or file:

```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    filename="sentinel_debug.log",
)
```

---

## 2. Inspecting Log Locations

- **System Diagnostics Log**: Generated during CLI execution or background task logging.
- **Scapy Debugging**: Enable Scapy layer dissection logging:
  ```python
  import scapy.all as scapy
  scapy.conf.debug_dissector = 1
  ```

---

## 3. Debugging Background Sniffer & Worker Threads

`PacketSniffer` captures errors in `self.last_error` and sets state to `CaptureState.ERROR`.

### Thread Inspection Snippet

```python
from core.sniffer import PacketSniffer

sniffer = PacketSniffer()
sniffer.start(interface="Ethernet")
print("Sniffer thread alive:", sniffer.thread.is_alive())
print("State:", sniffer.state)
if sniffer.last_error:
    print("Sniffer error:", sniffer.last_error)
```

---

## 4. Validating Rule Engine YAML Syntax

To inspect loaded signature rules programmatically:

```python
from detection.rule_engine import RuleEngine

engine = RuleEngine(rules_dir="rules")
print(f"Loaded {len(engine.rules)} rules:")
for rule in engine.rules:
    print(f"- [{rule.id}] {rule.name} ({rule.severity})")
```

---

## 5. Direct SQLite Inspection via Shell

Inspect persistent sessions and security alerts using the SQLite CLI:

```powershell
sqlite3 sentinel_data.db "SELECT id, session_type, status, packet_count FROM sessions ORDER BY id DESC LIMIT 5;"
sqlite3 sentinel_data.db "SELECT id, severity, rule_name, src_ip, message FROM alerts ORDER BY id DESC LIMIT 10;"
```
