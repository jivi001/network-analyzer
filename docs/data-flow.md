# End-to-End Data Flow Architecture

Complete visualization and tracing of packet, alert, and scan data flowing through `my-sentinel`.

## 1. Live Packet Data Flow

```text
Physical Network Interface (NIC)
             │
             ▼ Raw Ethernet Bytes
Scapy Sniffer Daemon Thread (scapy.sniff)
             │
             ▼ Raw Packet Object (Prn Callback)
Thread Queue (queue.Queue maxsize=5000)
             │
             ▼ Thread-Safe Queue Get
Packet Processor (core.processor.process_packet)
             │
             ├──► Decoded PacketInfo Dataclass
             │
             ├──────────────────────────┬──────────────────────────┐
             ▼                          ▼                          ▼
   StatsAggregator             Detection Pipeline             PcapWriter Stream
 (Total Packets, Bytes,     (Rule Engine, Anomaly, ARP)    (Raw Bytes -> file.pcap)
  Protocol Counts, Rates)               │
             │                          ▼ AlertInfo Dataclass
             │                     AlertManager
             │               (Ring Buffer + SQLite DB)
             │                          │
             └─────────────┬────────────┘
                           ▼
                 Rich Live Dashboard
             (Screen Table & Header Updates)
```

---

## 2. Network Scan Data Flow

```text
User Input (Target IP / CIDR / Hostname)
             │
             ▼
target_validation() & scan_profile allowlist check
             │
             ▼
NetworkScanner.scan(target, scan_type)
             │
             ▼
python-nmap API invocation (arguments: profile args + --host-timeout)
             │
             ▼
XML Output Parsing (_parse_results) -> List[HostInfo]
             │
             ├──► Database.save_scan_result(result)
             ├──► Database.save_host(host)
             │
             ▼
Rich Scan Results View (Table & Panel Output)
```
