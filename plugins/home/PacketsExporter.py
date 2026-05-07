from core.interfaces import IPacketExporter
from scapy.utils import wrpcap
from scapy.packet import Packet
from typing import List, Any
from collections.abc import Iterable

class BasicPacketExporter(IPacketExporter):
    def export(self, packets: List[Any], path: str) -> bool:
        try:
            if packets is None:
                return False

            if not isinstance(packets, Iterable):
                return False

            if not all(isinstance(pkt, Packet) for pkt in packets):
                return False

            if not all(isinstance(pkt, Packet) for pkt in packets):
                return False

            wrpcap(path, packets)

            print(f"[Exporter] Packets exported to {path}")
            return True

        except Exception as e:
            print(f"[Exporter] Export failed: {e}")
            return False