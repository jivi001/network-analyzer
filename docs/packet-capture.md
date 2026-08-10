# Packet Capture & Streaming Engine (`core/sniffer.py`)

## 1. Overview

Packet capture in `my-sentinel` is driven by `PacketSniffer` in `core/sniffer.py`. It wraps Scapy's `scapy.sniff` function inside a dedicated daemon background thread to perform non-blocking packet capture across network interfaces.

---

## 2. Sniffer State Machine

```text
  ┌──────┐    start()     ┌──────────┐    _sniff_loop()    ┌─────────┐
  │ IDLE ├───────────────►│ STARTING ├────────────────────►│ RUNNING │
  └──────┘                └────┬─────┘                     └────┬────┘
                               │                                │
                       Exception                                │ stop()
                               ▼                                ▼
                          ┌─────────┐                      ┌──────────┐
                          │  ERROR  │                      │ STOPPING │
                          └─────────┘                      └────┬─────┘
                                                                │
                                                                ▼
                                                           ┌─────────┐
                                                           │ STOPPED │
                                                           └─────────┘
```

---

## 3. Class Reference: `PacketSniffer`

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `callback` | `Optional[Callable]` | Function invoked for each captured raw Scapy packet. |
| `bpf_filter` | `str` | Active BPF filter string passed to `scapy.sniff(filter=...)`. |
| `running` | `threading.Event` | Synchronized boolean flag indicating active capture. |
| `_state` | `CaptureState` | Enum state: `IDLE`, `STARTING`, `RUNNING`, `STOPPING`, `STOPPED`, `ERROR`. |
| `interface` | `Optional[str]` | Target network interface name (defaults to `scapy.conf.iface`). |
| `last_error` | `Optional[str]` | String error message if capture fails or drops into `ERROR` state. |

---

## 4. Method Reference

### `start(interface=None, bpf_filter="", callback=None)`
- Sets `running` event and transitions state to `STARTING`.
- Resolves interface via `scapy.conf.iface` if `interface` is omitted or empty.
- Spawns background daemon thread target `_sniff_loop(interface)`.

### `_sniff_loop(interface)`
- Executes `scapy.sniff()` with arguments:
  - `iface`: Target interface name
  - `filter`: BPF filter string
  - `prn`: Packet callback wrapper (`self._process_packet`)
  - `stop_filter`: `lambda p: not self.running.is_set()`
  - `store`: `0` (**Critical: Prevents memory leak by telling Scapy not to accumulate packets in RAM**)

### `stop()`
- Sets state to `STOPPING`, clears `running` event, and joins background sniffing thread with `timeout=2.0s`.

### `restart_with_filter(bpf_filter)`
- Thread-safe stop and restart using a updated BPF filter string.

---

## 5. BPF Filter Validation (`sentinel.py`)

BPF filter strings entered by the user are validated prior to sniffer execution using `validate_bpf_filter()`:
- Rejects unclosed quotes, parentheses, shell injections, or malicious symbols.
- Test compiles filter via Scapy syntax check to prevent runtime sniffer crashes.
