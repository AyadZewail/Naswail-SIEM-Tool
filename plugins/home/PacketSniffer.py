from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import AsyncSniffer, rdpcap
import pandas as pd

from core.interfaces import IPacketSniffer

class PacketSnifferThread(QThread):
    _packet_captured = pyqtSignal(list)  # emit packets in batches

    def __init__(self):
        super().__init__()
        self._running = False
        self._source_type = None
        self._source_value = None
        self._sniffer = None
        self._packet_batch = []

    @property
    def packet_captured(self):
        return self._packet_captured

    def start(self) -> None:
        self._running = True
        super().start()

    def stop(self) -> None:
        self._running = False
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
        self.quit()
        self.wait()  # ensure thread fully stops

    def is_running(self) -> bool:
        return self._running

    def set_source(self, source_type: str, source_value: str) -> None:
        """
        source_type: 'live', 'pcap', or 'csv'
        source_value: interface name for live or file path for pcap/csv
        """
        self._source_type = source_type
        self._source_value = source_value

    def _emit_packet(self, packet):
        self._packet_batch.append(packet)
        if len(self._packet_batch) >= 150:  # batch size
            self._packet_captured.emit(self._packet_batch)
            self._packet_batch = []

    def _flush_batch(self):
        if self._packet_batch:
            self._packet_captured.emit(self._packet_batch)
            self._packet_batch = []

    def run(self):
        if not self._source_type:
            raise RuntimeError("Source not set; call set_source() before start().")
        try:
            if self._source_type == 'live':
                # Use AsyncSniffer to avoid blocking
                self._sniffer = AsyncSniffer(
                    prn=self._emit_packet,
                    # iface=self._source_value,
                    store=False,
                    promisc=True
                )
                self._sniffer.start()

                # Keep thread alive while sniffer is running
                while self._running and self._sniffer.running:
                    self.msleep(100)  # 100ms sleep to reduce CPU usage

                if self._sniffer.running:
                    self._sniffer.stop()

                self._flush_batch()

            elif self._source_type == 'pcap':
                packets = rdpcap(self._source_value)
                for pkt in packets:
                    if not self._running:
                        break
                    self._emit_packet(pkt)
                self._flush_batch()

            elif self._source_type == 'csv':
                df = pd.read_csv(self._source_value)
                for _, row in df.iterrows():
                    if not self._running:
                        break
                    self._emit_packet(row)
                self._flush_batch()

            else:
                raise ValueError(f"Unknown source_type: {self._source_type}")

        except Exception as e:
            print(f"[PacketSnifferThread] Error in run(): {e}")
        finally:
            self._running = False
