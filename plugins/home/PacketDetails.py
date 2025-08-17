from PyQt6.QtCore import QStringListModel
from core.interfaces import IPacketDetails
from typing import Any, List

class BasicPacketDetails(IPacketDetails):
    def __init__(self):
        """pass"""

    def extract_details(self, packet: Any) -> List[str]:
        try:
            details = packet.show(dump=True)
            details_list = details.split("\n")
            return details_list

        except Exception as e:
            print(f"[BasicPacketDetails] Error extracting details: {e}")
            return []
