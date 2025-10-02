from PyQt6.QtCore import QThread, pyqtSignal
from abc import ABC
import pandas as pd
from scapy.all import sniff, rdpcap

from core.interfaces import IPacketSniffer

class PacketSnifferThread(QThread):
    # the actual Qt signal
    _packet_captured = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self._running = False
        self._source_type = None
        self._source_value = None

    # fulfill the interface property
    @property
    def packet_captured(self):
        return self._packet_captured

    # override QThread.start() but keep the interface signature
    def start(self) -> None:
        self._running = True
        super().start()

    def stop(self) -> None:
        self.quit()
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def set_source(self, source_type: str, source_value: str) -> None:
        """
        source_type: 'live', 'pcap', or 'csv'
        source_value: interface name for live or file path for pcap/csv
        """
        self._source_type = source_type
        self._source_value = source_value

    def run(self):
        if not self._source_type:
            raise RuntimeError("Source not set; call set_source() before start().")
        try:
            if self._source_type == 'live':
                # sniff until stop() is called
                sniff(
                    prn=self._emit_packet,
                    promisc=True,
                    store=False,
                    stop_filter=lambda _: not self._running
                )

            elif self._source_type == 'pcap':
                packets = rdpcap(self._source_value)
                print("UEUWUWU")
                for pkt in packets:
                    if not self._running:
                        break
                    self._emit_packet(pkt)

            elif self._source_type == 'csv':
                df = pd.read_csv(self._source_value)
                for _, row in df.iterrows():
                    if not self._running:
                        break
                    self._emit_packet(row)

            else:
                raise ValueError(f"Unknown source_type: {self._source_type}")

        except Exception as e:
            print(f"[PacketSnifferThread] Error in run(): {e}")
        finally:
            self._running = False

    def _emit_packet(self, packet):
        # emit via the Qt signal
        self._packet_captured.emit(packet)