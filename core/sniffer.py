import threading
import scapy.all as scapy
from typing import Callable, Optional, List


class PacketSniffer:
    """Live Packet Capture Engine using Scapy."""

    def __init__(self, callback: Optional[Callable] = None):
        """
        Initializes the PacketSniffer.

        Args:
            callback (Optional[Callable]): Function to call with each captured raw packet.
        """
        self.callback = callback
        self.bpf_filter = ""
        self.running = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        self.raw_packets: List = []
        self.interface: Optional[str] = None

    def start(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        callback: Optional[Callable] = None,
    ):
        """
        Starts the packet sniffer in a background thread.

        Args:
            interface (Optional[str]): The network interface to sniff on.
            bpf_filter (str): BPF filter string to apply.
            callback (Optional[Callable]): Callback for each sniffed packet.
        """
        with self.lock:
            if self.running.is_set():
                return
            if callback is not None:
                self.callback = callback
            self.running.set()
            self.bpf_filter = bpf_filter or ""
            self.raw_packets.clear()

            if not interface:
                interface = scapy.conf.iface
            self.interface = interface

            self.thread = threading.Thread(
                target=self._sniff_loop, args=(interface,), daemon=True
            )
            self.thread.start()

    def _sniff_loop(self, interface: str):
        """Internal sniffing loop run in a background thread."""
        try:
            scapy.sniff(
                iface=interface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self._process_packet,
                stop_filter=lambda p: not self.running.is_set(),
                store=0,
            )
        except Exception as e:
            from rich.console import Console

            Console().print(f"[bold red][!] Sniffer error:[/bold red] {e}")
            self.running.clear()
        finally:
            self.running.clear()

    def _process_packet(self, packet):
        """Callback for each sniffed packet."""
        with self.lock:
            self.raw_packets.append(packet)
        if self.callback:
            try:
                self.callback(packet)
            except Exception as e:
                pass

    def stop(self):
        """Stops the packet sniffer."""
        with self.lock:
            self.running.clear()
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=2.0)

    def set_filter(self, bpf_filter: str):
        """Sets a new BPF filter."""
        with self.lock:
            self.bpf_filter = bpf_filter

    def restart_with_filter(self, bpf_filter: str):
        """Restart capture using a new BPF filter."""
        interface = self.interface
        callback = self.callback
        self.stop()
        self.start(interface=interface, bpf_filter=bpf_filter, callback=callback)

    def is_running(self) -> bool:
        """Returns True if the sniffer is running."""
        return self.running.is_set()

    def get_raw_packets(self) -> List:
        """Returns the list of captured raw packets."""
        with self.lock:
            return list(self.raw_packets)
