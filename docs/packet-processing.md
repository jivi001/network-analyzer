# Packet Decoding & Pipeline (`core/processor.py`)

## 1. Overview

`core/processor.py` contains `process_packet(raw_packet, packet_id)`, which decodes raw Scapy packet layers into normalized `PacketInfo` dataclasses.

---

## 2. Packet Processing Lifecycle

```text
  Raw Scapy Packet (Ethernet / IP / ARP)
                   │
                   ▼
       process_packet(raw, id)
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
    Ether / ARP           IP Layer
   (MAC Binding)    ┌────────┼────────┐
                    ▼        ▼        ▼
                   TCP      UDP      ICMP
                    │        │
                    ▼        ▼
                 Flags      DNS / QR
                   │        │
                   └────┬───┘
                        ▼
            PacketInfo Dataclass
```

---

## 3. Layer Parsing Details

### Ethernet & ARP (`Ether`, `ARP`)
- Extracts Ethernet source/destination MAC addresses (`src_mac`, `dst_mac`).
- If ARP opcode is `1` (`Request`), sets `info = "ARP Request Who has {pdst}? Tell {psrc}"`.
- If ARP opcode is `2` (`Reply`), sets `info = "ARP Reply {psrc} is at {hwsrc}"`.

### IPv4 (`IP`)
- Extracts `src_ip`, `dst_ip`, and `ttl`.

### TCP (`TCP`)
- Extracts `src_port`, `dst_port`.
- Translates port numbers to service names using `resolve_service(src_port, dst_port)`.
- Parses TCP flag characters (`F`, `S`, `R`, `P`, `A`, `U`, `E`, `C`) into human-readable lists (`FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `ECE`, `CWR`).
- Formats `info` string with seq, ack, window size, and payload length.

### UDP & DNS (`UDP`, `DNS`, `DNSQR`)
- Extracts UDP `src_port`, `dst_port`.
- If packet contains `DNS` layer with `DNSQR` (query record):
  - Sets protocol to `"DNS"`.
  - Decodes domain name (`qname`) cleanly handling UTF-8 bytes or string attributes.
  - Formats `info = "DNS Query: {domain_name}"`.

### ICMP (`ICMP`)
- Sets protocol to `"ICMP"`.
- Formats `info = "ICMP Type={type} Code={code}"`.

---

## 4. Exception Resilience & Null Safety

`process_packet()` guards against malformed packets:
- Validates `hasattr(raw_packet, "haslayer")`.
- Safely handles missing timestamp or microsecond conversion errors by falling back to `time.time()`.
- Wraps string decodes in `try...except` to prevent malformed payload crashes.
- Returns `None` if the input raw packet is unparseable.
