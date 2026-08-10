import enum
import logging
import threading
import scapy.all as scapy
from typing import Callable, Optional, List

logger = logging.getLogger(__name__)


class CaptureState(enum.Enum):
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


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
        self._state = CaptureState.IDLE
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        self.interface: Optional[str] = None
        self.last_error: Optional[str] = None

    @property
    def state(self) -> CaptureState:
        with self.lock:
            return self._state

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
            self._state = CaptureState.STARTING
            self.bpf_filter = bpf_filter or ""
            self.last_error = None

            if not interface:
                interface = scapy.conf.iface
            self.interface = interface

            self.thread = threading.Thread(
                target=self._sniff_loop, args=(interface,), daemon=True
            )
            self.thread.start()

    def _sniff_loop(self, interface: str):
        """Internal sniffing loop run in a background thread."""
        with self.lock:
            self._state = CaptureState.RUNNING
        try:
            scapy.sniff(
                iface=interface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self._process_packet,
                stop_filter=lambda p: not self.running.is_set(),
                store=0,
            )
        except Exception as e:
            err_msg = f"Sniffer error: {e}"
            logger.error(err_msg)
            with self.lock:
                self.last_error = str(e)
                self._state = CaptureState.ERROR
            self.running.clear()
        finally:
            self.running.clear()
            with self.lock:
                if self._state != CaptureState.ERROR:
                    self._state = CaptureState.STOPPED

    def _process_packet(self, packet):
        """Callback for each sniffed packet."""
        if self.callback:
            try:
                self.callback(packet)
            except Exception as e:
                logger.debug(f"Packet callback error: {e}")

    def stop(self):
        """Stops the packet sniffer."""
        with self.lock:
            self._state = CaptureState.STOPPING
            self.running.clear()
            thread = self.thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)
        with self.lock:
            if self._state != CaptureState.ERROR:
                self._state = CaptureState.STOPPED

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

