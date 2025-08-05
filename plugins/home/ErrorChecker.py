from core.interfaces import IErrorChecker
from scapy.all import raw
from datetime import datetime
from typing import Any, Optional

class BasicErrorChecker(IErrorChecker):
    def __init__(self, corrupted_packet_list=None, logger=None):
        """
        TEMP: Accepts references to external log and list until decoupled later.
        """
        self.corrupted_packet_list = corrupted_packet_list
        self.logger = logger

    def is_corrupted(self, packet: Any) -> Optional[bool]:
        try:
            if hasattr(packet, 'chksum'):
                original_checksum = packet.chksum

                # Force recalculation
                packet.chksum = None
                recalculated_bytes = raw(packet)
                recalculated_packet = packet.__class__(recalculated_bytes)
                recalculated_checksum = recalculated_packet.chksum

                if original_checksum == recalculated_checksum:
                    return False
                else:
                    self.corrupted_packet_list.append(packet)
                    current_time = datetime.now().strftime("%H:%M:%S")
                    self.logger.append(f"{current_time} - A packet has been corrupted")
                    return True
            else:
                return False
        except Exception as e:
            print(f"[BasicErrorChecker] Error verifying checksum: {e}")
            return None
