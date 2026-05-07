import sys
import os
import pytest
from scapy.utils import rdpcap
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plugins.home.PacketDetails import BasicPacketDetails  # adjust to your module path


PCAP_PATH = os.path.join(
    os.path.dirname(__file__),
    "testingPackets.pcap"
)

@pytest.fixture
def real_packet():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")
    return rdpcap(PCAP_PATH)[0]

def test_real_packet_returns_nonempty_list(real_packet):
    result = BasicPacketDetails().extract_details(real_packet)
    assert isinstance(result, list)
    assert len(result) > 0
    assert all(isinstance(line, str) for line in result)