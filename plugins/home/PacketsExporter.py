from core.interfaces import IPacketExporter
from scapy.utils import wrpcap
from typing import List, Any

class BasicPacketExporter(IPacketExporter):
    def export(self, packets: List[Any], path: str) -> bool:
        try:
            wrpcap(path, packets)
            print(f"[Exporter] Packets exported to {path}")
            return True
        except Exception as e:
            print(f"[Exporter] Export failed: {e}")
            return False