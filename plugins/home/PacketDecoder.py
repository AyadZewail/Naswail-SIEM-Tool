from core.interfaces import IPacketDecoder
from PyQt6.QtCore import QStringListModel
from typing import Any, List

class BasicPacketDecoder(IPacketDecoder):
    def __init__(self):
        """
        Temporary coupling to the UI component, to be removed later.
        """

    def set_ui(self, list_view):
        self.list_view = list_view
    
    def decode(self, packet: Any) -> List[str]:
        try:
            raw_content = bytes(packet)
            formatted_content = []
            for i in range(0, len(raw_content), 16):
                chunk = raw_content[i:i + 16]
                hex_part = " ".join(f"{byte:02x}" for byte in chunk)
                ascii_part = "".join(
                    chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
                )
                formatted_content.append(f"{hex_part:<48}  {ascii_part}")

            # TEMP: push result to UI
            model = QStringListModel()
            model.setStringList(formatted_content)
            self.list_view.setModel(model)

            return formatted_content

        except Exception as e:
            print(f"[BasicPacketDecoder] Error decoding packet: {e}")
            return []
