import sys
import os
import pytest
from scapy.utils import rdpcap
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.home.PacketDecoder import BasicPacketDecoder


PCAP_PATH = os.path.join(
    os.path.dirname(__file__),
    "testingPackets.pcap"
)


@pytest.fixture
def real_packet():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")

    packets = rdpcap(PCAP_PATH)

    if len(packets) == 0:
        pytest.skip("pcap contains no packets")

    return packets[0]


def test_decode_valid_packet(real_packet):
    decoder = BasicPacketDecoder()

    result = decoder.decode(real_packet)

    assert isinstance(result, list)
    assert len(result) > 0
    assert all(isinstance(line, str) for line in result)


def test_decode_empty():
    decoder = BasicPacketDecoder()

    result = decoder.decode(b"")

    assert result == []


def test_decode_invalid_input():
    decoder = BasicPacketDecoder()

    result = decoder.decode(None)

    assert result == []


def test_decode_known_bytes():
    decoder = BasicPacketDecoder()

    packet = bytes(range(16))
    result = decoder.decode(packet)

    assert len(result) == 1
    assert "00 01 02 03" in result[0]


def test_decode_multiple_lines():
    decoder = BasicPacketDecoder()

    packet = bytes(range(32))
    result = decoder.decode(packet)

    assert len(result) == 2


def test_non_printable_ascii():
    decoder = BasicPacketDecoder()

    packet = b"\x00\x01ABC\x02\x03"
    result = decoder.decode(packet)

    assert "." in result[0]
    assert "ABC" in result[0]