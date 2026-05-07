import os
import pytest
from scapy.utils import rdpcap
from scapy.all import IP, TCP, UDP, ICMP

from plugins.home.ProtocolExtractor import BasicProtocolExtractor


# portable relative path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_PATH = os.path.join(BASE_DIR, "testingPackets.pcap")


@pytest.fixture
def extractor():
    return BasicProtocolExtractor()


@pytest.fixture
def packets():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")

    pkts = rdpcap(PCAP_PATH)

    if len(pkts) == 0:
        pytest.skip("pcap contains no packets")

    return pkts


# ── transport layer detection ─────────────────────────

def test_tcp_packet_returns_tcp(extractor, packets):
    tcp_packet = next((p for p in packets if p.haslayer(TCP)), None)

    if tcp_packet is None:
        pytest.skip("no TCP packets found")

    result = extractor.extract_protocol(tcp_packet[TCP])

    assert result in ["http", "https", "ssh", "smtp", "imap", "pop3", "rdp", "tcp"]


def test_udp_packet_returns_udp_or_specific_protocol(extractor, packets):
    udp_packet = next((p for p in packets if p.haslayer(UDP)), None)

    if udp_packet is None:
        pytest.skip("no UDP packets found")

    result = extractor.extract_protocol(udp_packet[UDP])

    assert result in ["dns", "dhcp", "ntp", "udp"]


def test_icmp_packet_returns_icmp(extractor, packets):
    icmp_packet = next((p for p in packets if p.haslayer(ICMP)), None)

    if icmp_packet is None:
        pytest.skip("no ICMP packets found")

    result = extractor.extract_protocol(icmp_packet)

    assert result == "icmp"


# ── specific port-based protocols ────────────────────

def test_http_detection(extractor):
    packet = TCP(sport=12345, dport=80)

    result = extractor.extract_protocol(packet)

    assert result == "http"


def test_https_detection(extractor):
    packet = TCP(sport=12345, dport=443)

    result = extractor.extract_protocol(packet)

    assert result == "https"


def test_ssh_detection(extractor):
    packet = TCP(sport=22, dport=50000)

    result = extractor.extract_protocol(packet)

    assert result == "ssh"


def test_smtp_detection(extractor):
    packet = TCP(sport=25, dport=40000)

    result = extractor.extract_protocol(packet)

    assert result == "smtp"


def test_imap_detection(extractor):
    packet = TCP(sport=143, dport=50000)

    result = extractor.extract_protocol(packet)

    assert result == "imap"


def test_pop3_detection(extractor):
    packet = TCP(sport=110, dport=50000)

    result = extractor.extract_protocol(packet)

    assert result == "pop3"


def test_rdp_detection(extractor):
    packet = TCP(sport=3389, dport=50000)

    result = extractor.extract_protocol(packet)

    assert result == "rdp"


def test_dns_detection(extractor):
    packet = UDP(sport=53, dport=50000)

    result = extractor.extract_protocol(packet)

    assert result == "dns"


def test_dhcp_detection(extractor):
    packet = UDP(sport=67, dport=68)

    result = extractor.extract_protocol(packet)

    assert result == "dhcp"


def test_ntp_detection(extractor):
    packet = UDP(sport=123, dport=50000)

    result = extractor.extract_protocol(packet)

    assert result == "ntp"


# ── fallback behavior ─────────────────────────────────

def test_unknown_protocol_returns_other(extractor):
    class FakePacket:
        def haslayer(self, layer):
            return False

    result = extractor.extract_protocol(FakePacket())

    assert result == "other"


def test_ip_proto_fallback_tcp(extractor):
    packet = IP(proto=6)

    result = extractor.extract_protocol(packet)

    assert result == "tcp"


def test_ip_proto_fallback_udp(extractor):
    packet = IP(proto=17)

    result = extractor.extract_protocol(packet)

    assert result == "udp"


def test_ip_proto_fallback_icmp(extractor):
    packet = IP(proto=1)

    result = extractor.extract_protocol(packet)

    assert result == "icmp"


def test_unknown_ip_proto_returns_other(extractor):
    packet = IP(proto=255)

    result = extractor.extract_protocol(packet)

    assert result == "other"


# ── exception handling ────────────────────────────────

def test_invalid_packet_returns_unknown(extractor):
    result = extractor.extract_protocol(None)

    assert result == "unknown"