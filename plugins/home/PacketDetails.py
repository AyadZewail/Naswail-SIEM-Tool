from PyQt6.QtCore import QStringListModel
from core.interfaces import IPacketDetails
from typing import Any, List

class BasicPacketDetails(IPacketDetails):
    def __init__(self):
        """pass"""
    
    def set_ui(self, list_view):
        self.list_view = list_view

    def extract_details(self, packet: Any) -> List[str]:
        try:
            details = packet.show(dump=True)
            details_list = details.split("\n")

            # TEMPORARY UI coupling
            model = QStringListModel()
            model.setStringList(details_list)
            self.list_view.setModel(model)

            return details_list

        except Exception as e:
            print(f"[BasicPacketDetails] Error extracting details: {e}")
            return []
