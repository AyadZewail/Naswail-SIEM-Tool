import pytest
import os
from scapy.utils import rdpcap

from plugins.tools.NetworkActivityAnalyzer import NetworkActivityAnalyzer
from models.network_activity import NetworkActivity


# -------------------------
# PCAP path (relative)
# -------------------------

PCAP_PATH = os.path.join(
    os.path.dirname(__file__),
    "packet_file6.pcap"
)


# -------------------------
# Fixtures
# -------------------------

@pytest.fixture
def packets():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("PCAP file not found")

    return rdpcap(PCAP_PATH)


@pytest.fixture
def analyzer():
    return NetworkActivityAnalyzer()


# -------------------------
# Tests
# -------------------------

def test_returns_list_of_activities(analyzer, packets):
    result = analyzer.extract_activities(packets)

    assert isinstance(result, list)


def test_returns_network_activity_objects(analyzer, packets):
    result = analyzer.extract_activities(packets)

    if not result:
        pytest.skip("No analyzable packets in PCAP")

    assert all(isinstance(x, NetworkActivity) for x in result)


def test_activity_strings_are_non_empty(analyzer, packets):
    result = analyzer.extract_activities(packets)

    if not result:
        pytest.skip("No analyzable packets in PCAP")

    assert all(isinstance(x.activity, str) for x in result)
    assert all(len(x.activity) > 0 for x in result)


def test_mac_addresses_exist_when_ethernet_present(analyzer, packets):
    result = analyzer.extract_activities(packets)

    for pkt, activity in zip(packets, result):
        if pkt.haslayer("Ethernet"):
            assert activity.mac_of_device != "N/A"


def test_http_or_dns_activity_detected(analyzer, packets):
    result = analyzer.extract_activities(packets)

    if not result:
        pytest.skip("No HTTP/DNS traffic found in PCAP")

    activities = [a.activity.lower() for a in result]

    assert any("http" in a for a in activities) or any("dns" in a for a in activities)