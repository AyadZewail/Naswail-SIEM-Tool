import sys
import os
import pytest
from scapy.utils import rdpcap
from scapy.all import IP, TCP, UDP
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plugins.home.PacketFilter import BasicPacketFilter


PCAP_PATH = os.path.join(
    os.path.dirname(__file__),
    "testingPackets.pcap"
)


class SimpleProtocolExtractor:
    """Real stub — just reads the scapy layer directly, no mocks."""
    def extract_protocol(self, packet):
        if packet.haslayer("TCP"):
            return "TCP"
        elif packet.haslayer("UDP"):
            return "UDP"
        elif packet.haslayer("ICMP"):
            return "ICMP"
        elif packet.haslayer("ARP"):
            return "ARP"
        return "Unknown"


@pytest.fixture
def packets():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")
    return rdpcap(PCAP_PATH)

@pytest.fixture
def filter():
    return BasicPacketFilter(protocol_extractor=SimpleProtocolExtractor())


# ── no criteria ───────────────────────────────────────

def test_empty_criteria_returns_all_packets(filter, packets):
    result = filter.filter_packets(packets, {})
    assert len(result) == len(packets)

def test_empty_packet_list_returns_empty(filter):
    assert filter.filter_packets([], {}) == []


# ── protocol filter ───────────────────────────────────

def test_filter_by_tcp_returns_only_tcp(filter, packets):
    result = filter.filter_packets(packets, {"protocols": ["TCP"]})
    assert all(p.haslayer(TCP) for p in result)

def test_filter_by_udp_returns_only_udp(filter, packets):
    result = filter.filter_packets(packets, {"protocols": ["UDP"]})
    assert all(p.haslayer(UDP) for p in result)

def test_filter_by_nonexistent_protocol_returns_empty(filter, packets):
    result = filter.filter_packets(packets, {"protocols": ["FAKEPROTO"]})
    assert result == []


# ── ip filters ────────────────────────────────────────

def test_src_ip_filter_matches_correctly(filter, packets):
    ip_packets = [p for p in packets if p.haslayer(IP)]
    if not ip_packets:
        pytest.skip("no IP packets in pcap")
    target_src = ip_packets[0][IP].src
    result = filter.filter_packets(packets, {"src_ip": target_src})
    assert all(p[IP].src == target_src for p in result if p.haslayer(IP))

def test_dst_ip_filter_matches_correctly(filter, packets):
    ip_packets = [p for p in packets if p.haslayer(IP)]
    if not ip_packets:
        pytest.skip("no IP packets in pcap")
    target_dst = ip_packets[0][IP].dst
    result = filter.filter_packets(packets, {"dst_ip": target_dst})
    assert all(p[IP].dst == target_dst for p in result if p.haslayer(IP))

def test_bogus_src_ip_returns_empty(filter, packets):
    result = filter.filter_packets(packets, {"src_ip": "256.0.0.0"})
    assert result == []


# ── port filter ───────────────────────────────────────

def test_port_filter_returns_matching_packets(filter, packets):
    tcp_packets = [p for p in packets if p.haslayer(TCP)]
    if not tcp_packets:
        pytest.skip("no TCP packets in pcap")
    target_port = tcp_packets[0][TCP].dport
    result = filter.filter_packets(packets, {"port": str(target_port)})
    assert len(result) > 0
    for p in result:
        if p.haslayer(TCP):
            assert p[TCP].sport == target_port or p[TCP].dport == target_port

def test_invalid_port_string_returns_empty(filter, packets):
    result = filter.filter_packets(packets, {"port": "not_a_port"})
    assert result == []


# ── direction filter ──────────────────────────────────

def test_direction_inside_returns_only_local_traffic(filter, packets):
    import ipaddress
    result = filter.filter_packets(packets, {"direction": "Inside"})
    for p in result:
        if p.haslayer(IP):
            assert ipaddress.ip_address(p[IP].src).is_private
            assert ipaddress.ip_address(p[IP].dst).is_private

def test_direction_any_returns_all_packets(filter, packets):
    result_any = filter.filter_packets(packets, {"direction": "Any"})
    result_none = filter.filter_packets(packets, {})
    assert len(result_any) == len(result_none)


# ── mac filter ────────────────────────────────────────

def test_mac_filter_matches_correctly(filter, packets):
    eth_packets = [p for p in packets if p.haslayer("Ethernet")]
    if not eth_packets:
        pytest.skip("no Ethernet packets in pcap")
    target_mac = eth_packets[0]["Ethernet"].src
    result = filter.filter_packets(packets, {"mac_addresses": [target_mac]})
    assert len(result) > 0
    assert all(p["Ethernet"].src == target_mac for p in result if p.haslayer("Ethernet"))

def test_bogus_mac_returns_empty(filter, packets):
    result = filter.filter_packets(packets, {"mac_addresses": ["00:00:00:00:00:00"]})
    assert result == []


# ── combined filters ──────────────────────────────────

def test_src_ip_and_protocol_combined(filter, packets):
    tcp_packets = [p for p in packets if p.haslayer(TCP) and p.haslayer(IP)]
    if not tcp_packets:
        pytest.skip("no TCP/IP packets in pcap")
    target_src = tcp_packets[0][IP].src
    result = filter.filter_packets(packets, {"protocols": ["TCP"], "src_ip": target_src})
    assert all(p.haslayer(TCP) for p in result)
    assert all(p[IP].src == target_src for p in result if p.haslayer(IP))