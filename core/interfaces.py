"""
Core interfaces for the Naswail SIEM Tool.
These interfaces define the contracts that concrete implementations must follow.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
from scapy.packet import Packet  # for type hints 

class IPacketSniffer(ABC):
    @property
    @abstractmethod
    def packet_captured(self):
        """
        Signal (or signal-like object) emitted for each captured packet.
        """
        pass

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def is_running(self) -> bool:
        pass

    @abstractmethod
    def set_source(self, source_type: str, source_value: str) -> None:
        pass

class IPacketDecoder(ABC):
    @abstractmethod
    def decode(self, packet: Any) -> List[str]:
        """
        Converts a raw packet into a hex+ASCII string list.

        Args:
            packet: A raw packet object (e.g., from Scapy)

        Returns:
            A list of formatted strings, each line showing 16 bytes of hex + ASCII
        """
        pass

class IPacketDetails(ABC):
    @abstractmethod
    def extract_details(self, packet: Any) -> List[str]:
        """
        Extracts and formats detailed string representation of a packet.

        Args:
            packet: The packet object (e.g., Scapy packet)

        Returns:
            A list of strings, one for each line of the packet's detailed view.
        """
        pass

class IProtocolExtractor(ABC):
    @abstractmethod
    def extract_protocol(self, packet: Any) -> str:
        """
        Determines the application/service-layer protocol of a packet.

        Args:
            packet: A Scapy packet or similar

        Returns:
            A string like 'http', 'dns', 'tcp', etc.
        """
        pass

class IErrorChecker(ABC):
    @abstractmethod
    def is_corrupted(self, packet: Any) -> Optional[bool]:
        """
        Checks whether the packet's checksum is invalid.

        Args:
            packet: The packet to check.

        Returns:
            True if packet is corrupted, False if valid, None if error.
        """
        pass