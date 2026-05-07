import sys
import os
import pytest
from scapy.utils import rdpcap
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plugins.home.ErrorChecker import BasicErrorChecker


PCAP_PATH = os.path.join(
    os.path.dirname(__file__),
    "testingPackets.pcap"
)


@pytest.fixture
def corrupted_list():
    return []

@pytest.fixture
def logger():
    return []

@pytest.fixture
def checker(corrupted_list, logger):
    return BasicErrorChecker(corrupted_packet_list=corrupted_list, logger=logger)

@pytest.fixture
def real_packet():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")
    packets = rdpcap(PCAP_PATH)
    for pkt in packets:
        if pkt.haslayer("IP"):
            return pkt["IP"]
    pytest.skip("no IP packet found in pcap")


def test_valid_packet_returns_false(checker, real_packet):
    assert checker.is_corrupted(real_packet) is False

def test_valid_packet_not_added_to_list(checker, corrupted_list, real_packet):
    checker.is_corrupted(real_packet)
    assert len(corrupted_list) == 0

def test_valid_packet_nothing_logged(checker, logger, real_packet):
    checker.is_corrupted(real_packet)
    assert len(logger) == 0

def test_corrupted_packet_returns_true(checker, real_packet):
    real_packet.chksum = "0x1234"
    assert checker.is_corrupted(real_packet) is True

def test_corrupted_packet_added_to_list(checker, corrupted_list, real_packet):
    real_packet.chksum = "0x1234"
    checker.is_corrupted(real_packet)
    assert len(corrupted_list) == 1

def test_corrupted_packet_logs_message(checker, logger, real_packet):
    real_packet.chksum = "0x1234"
    checker.is_corrupted(real_packet)
    assert len(logger) == 1
    assert "corrupted" in logger[0].lower()

def test_none_packet_returns_none(checker):
    assert checker.is_corrupted(None) is None