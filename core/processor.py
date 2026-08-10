import time
from datetime import datetime
from typing import Optional
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
from storage.models import PacketInfo
from utils.constants import resolve_service, TCP_FLAGS


def process_packet(raw_packet, packet_id: int) -> Optional[PacketInfo]:
    """
    Decodes a raw Scapy packet into a PacketInfo dataclass.

    Args:
        raw_packet: The Scapy packet.
        packet_id (int): A unique identifier for the packet.

    Returns:
        PacketInfo: The decoded packet information or None if raw_packet is invalid.
    """
    if raw_packet is None or not hasattr(raw_packet, "haslayer"):
        return None
    try:
        ts_float = float(raw_packet.time) if hasattr(raw_packet, "time") else time.time()
        dt = datetime.fromtimestamp(ts_float)
        timestamp_str = dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
        date_str = dt.strftime("%Y-%m-%d")
        length = len(raw_packet) if hasattr(raw_packet, "__len__") else 0
    except Exception:
        return None

    src_mac = ""
    dst_mac = ""
    src_ip = ""
    dst_ip = ""
    protocol = "Other"
    src_port = 0
    dst_port = 0
    flags_list = []
    flags_raw = ""
    service = "-"
    info = ""
    ttl = 0
    dns_query = ""
    dns_type = ""

    if raw_packet.haslayer(Ether):
        src_mac = raw_packet[Ether].src
        dst_mac = raw_packet[Ether].dst

    if raw_packet.haslayer(ARP):
        protocol = "ARP"
        arp = raw_packet[ARP]
        op = "Request" if arp.op == 1 else ("Reply" if arp.op == 2 else str(arp.op))
        info = f"ARP {op} Who has {arp.pdst}? Tell {arp.psrc}"
        src_ip = arp.psrc
        dst_ip = arp.pdst
        src_mac = arp.hwsrc if hasattr(arp, "hwsrc") else src_mac
        dst_mac = arp.hwdst if hasattr(arp, "hwdst") else dst_mac
    elif raw_packet.haslayer(IP):
        ip_layer = raw_packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = ip_layer.ttl

        if raw_packet.haslayer(TCP):
            protocol = "TCP"
            tcp = raw_packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            service = resolve_service(src_port, dst_port)
            flags_raw = str(tcp.flags)
            flags_list = [TCP_FLAGS[c] for c in flags_raw if c in TCP_FLAGS]
            flag_str = ",".join(flags_list) if flags_list else "NONE"
            info = f"{src_port} > {dst_port} [{flag_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(tcp.payload)}"

        elif raw_packet.haslayer(UDP):
            protocol = "UDP"
            udp = raw_packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            service = resolve_service(src_port, dst_port)

            if raw_packet.haslayer(DNS):
                protocol = "DNS"
                if raw_packet.haslayer(DNSQR):
                    dns_qr = raw_packet[DNSQR]
                    if dns_qr.qname:
                        dns_query = (
                            dns_qr.qname.decode("utf-8", errors="ignore").rstrip(".")
                            if isinstance(dns_qr.qname, bytes)
                            else str(dns_qr.qname).rstrip(".")
                        )
                    dns_type = str(dns_qr.qtype)
                    info = f"DNS Query: {dns_query}"
                else:
                    info = f"DNS Response ({src_port} > {dst_port})"
            else:
                info = f"{src_port} > {dst_port} Len={udp.len}"

        elif raw_packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp = raw_packet[ICMP]
            service = "Ping / Control"
            info = f"ICMP Type={icmp.type} Code={icmp.code}"
        else:
            protocol = "IP"
            info = f"IP Protocol {ip_layer.proto}"

    return PacketInfo(
        id=packet_id,
        timestamp=ts_float,
        timestamp_str=timestamp_str,
        date_str=date_str,
        length=length,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        flags=flags_list,
        flags_raw=flags_raw,
        service=service,
        info=info,
        ttl=ttl,
        dns_query=dns_query,
        dns_type=dns_type,
        raw_packet=raw_packet,
    )
