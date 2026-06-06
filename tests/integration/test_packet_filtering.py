import pytest
import os
from scapy.all import rdpcap

from plugins.home.ProtocolExtractor import BasicProtocolExtractor
from plugins.home.PacketFilter import BasicPacketFilter

@pytest.fixture(scope="module")
def sample_packets():
    """
    Load a real PCAP file from the tests directory. 
    We slice the first 500 packets so the test stays fast.
    """
    pcap_path = os.path.join(os.path.dirname(__file__), "..", "packet_file6.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip(f"PCAP file not found at {pcap_path}")
    return rdpcap(pcap_path)[:500] 

@pytest.fixture
def packet_filter():
    """
    Provides the BasicPacketFilter injected with the real BasicProtocolExtractor,
    creating the integration under test.
    """
    extractor = BasicProtocolExtractor()
    return BasicPacketFilter(protocol_extractor=extractor)

def test_filter_by_protocol_layer(packet_filter, sample_packets):
    # Act
    criteria = {"protocols": ["tcp"]}
    filtered = packet_filter.filter_packets(sample_packets, criteria)
    
    # Assert
    # Make sure we didn't filter out everything (assuming the PCAP has TCP packets)
    assert len(filtered) > 0, "Expected at least some TCP packets in the sample."
    for packet in filtered:
        # Check against scapy to verify the integration worked
        assert packet.haslayer("TCP")

def test_filter_by_app_protocol_integration(packet_filter, sample_packets):
    """
    This specifically tests the integration with ProtocolExtractor.
    If we ask for 'http' or 'dns', the PacketFilter must rely on the ProtocolExtractor
    to identify them, since they are not basic scapy layers.
    """
    # Act
    criteria = {"protocols": ["http", "dns", "https"]}
    filtered = packet_filter.filter_packets(sample_packets, criteria)
    
    # Assert
    extractor = packet_filter.protocol_extractor
    for packet in filtered:
        # The extractor should agree that this packet is one of the requested protocols
        proto = extractor.extract_protocol(packet)
        # Note: the filter also matches if the layer itself is in the selected protocols,
        # but here we selected app protocols, so proto must match.
        assert proto in ["http", "dns", "https"]

def test_filter_multiple_criteria_integration(packet_filter, sample_packets):
    """
    Tests filtering on multiple dimensions simultaneously, including
    protocol extraction, IP addresses, and directions.
    """
    # Arrange
    criteria = {
        "protocols": ["udp"],
        "direction": "Outside"
    }
    
    # Act
    filtered = packet_filter.filter_packets(sample_packets, criteria)
    
    # Assert
    for packet in filtered:
        # 1. Must be UDP
        assert packet.haslayer("UDP")
        
        # 2. Must be "Outside" (meaning not local -> local)
        if packet.haslayer("IP"):
            src_local = packet_filter.is_local_ip(packet["IP"].src)
            dst_local = packet_filter.is_local_ip(packet["IP"].dst)
            assert not (src_local and dst_local)
