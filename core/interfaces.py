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

class IPacketStatistics(ABC):
    @abstractmethod
    def analyze(self, packets: List[Any], totals: dict, app_proto_counts: dict) -> List[str]:
        """
        Analyze and summarize packet statistics.

        Args:
            packets: Full list of captured packets.
            totals: Dict with counts of TCP, UDP, ICMP, etc.
            app_proto_counts: Dict of application protocol packet counts (http, ftp, dns, etc.)

        Returns:
            List of formatted statistics as strings (1 per line).
        """
        pass

class IPacketExporter(ABC):
    @abstractmethod
    def export(self, packets: List[Any], path: str) -> bool:
        """
        Export the given packets to a file.

        Args:
            packets: List of packet objects (e.g., Scapy packets)
            path: Output file path

        Returns:
            True if successful, False otherwise
        """
        pass

class IPacketFabricator(ABC):
    @abstractmethod
    def fabricate_and_send(self, src_ip: str, dst_ip: str, protocol: str, payload: Optional[str] = None) -> bool:
        """
        Crafts and sends a packet with the specified parameters.

        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            protocol (str): Application-layer protocol (e.g., 'TCP', 'UDP', 'ICMP', etc.)
            payload (str): Optional payload or message to include

        Returns:
            bool: True if sent successfully, False otherwise
        """
        pass

class IAnomalyDetector(ABC):
    @abstractmethod
    def check_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Determines whether a packet is anomalous based on internal detection logic.

        Returns:
            A dictionary describing the anomaly if detected, otherwise None.
        """
        pass