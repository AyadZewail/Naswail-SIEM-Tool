import os
import pytest
from scapy.utils import rdpcap

from plugins.home.PacketStatistics import BasicPacketStatistics


# portable relative path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_PATH = os.path.join(BASE_DIR, "testingPackets.pcap")


@pytest.fixture
def analyzer():
    return BasicPacketStatistics()


@pytest.fixture
def packets():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")

    pkts = rdpcap(PCAP_PATH)

    if len(pkts) == 0:
        pytest.skip("pcap contains no packets")

    return pkts


@pytest.fixture
def totals(packets):
    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    for pkt in packets:
        if pkt.haslayer("TCP"):
            tcp_count += 1
        elif pkt.haslayer("UDP"):
            udp_count += 1
        elif pkt.haslayer("ICMP"):
            icmp_count += 1

    return {
        "tcp": tcp_count,
        "udp": udp_count,
        "icmp": icmp_count,
    }


@pytest.fixture
def app_proto_counts():
    return {
        "total": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "other": 0,
        "http": 10,
        "https": 8,
        "dns": 5,
        "dhcp": 0,
        "ftp": 2,
        "telnet": 1,
    }


# ── normal behavior ───────────────────────────────────

def test_analyze_returns_list(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert isinstance(result, list)
    assert all(isinstance(line, str) for line in result)


def test_total_packet_count_correct(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert f"Total Packets: {len(packets)}" in result


def test_tcp_count_correct(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert f"TCP Packets: {totals['tcp']}" in result


def test_udp_count_correct(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert f"UDP Packets: {totals['udp']}" in result


def test_icmp_count_correct(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert f"ICMP Packets: {totals['icmp']}" in result


# ── statistical metrics ───────────────────────────────

def test_mean_exists(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert any("Mean:" in line for line in result)


def test_range_exists(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert any("Range:" in line for line in result)


def test_mode_exists(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert any("Mode:" in line for line in result)


def test_standard_deviation_exists(analyzer, packets, totals, app_proto_counts):
    result = analyzer.analyze(packets, totals, app_proto_counts)

    assert any("Standard Deviation:" in line for line in result)


# ── missing keys/defaults ─────────────────────────────

def test_missing_totals_defaults_to_zero(analyzer, packets, app_proto_counts):
    result = analyzer.analyze(packets, {}, app_proto_counts)

    assert "TCP Packets: 0" in result
    assert "UDP Packets: 0" in result
    assert "ICMP Packets: 0" in result


def test_missing_app_proto_defaults_to_zero(analyzer, packets, totals):
    result = analyzer.analyze(packets, totals, {})

    assert "DNS Packets: 0" in result
    assert "HTTP Packets: 0" in result
    assert "HTTPS Packets: 0" in result


# ── edge cases ────────────────────────────────────────

def test_empty_packet_list(analyzer, app_proto_counts):
    result = analyzer.analyze([], {}, app_proto_counts)

    assert "Total Packets: 0" in result


def test_invalid_totals_returns_error(analyzer, packets, app_proto_counts):
    result = analyzer.analyze(packets, None, app_proto_counts)

    assert result == ["Error generating statistics."]


def test_invalid_app_proto_counts_returns_error(analyzer, packets, totals):
    result = analyzer.analyze(packets, totals, None)

    assert result == ["Error generating statistics."]