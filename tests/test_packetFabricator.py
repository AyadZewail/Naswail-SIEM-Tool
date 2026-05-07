import pytest
from scapy.all import TCP, UDP, ICMP, DNS

from plugins.home.PacketFabricator import BasicPacketFabricator


@pytest.fixture
def fabricator():
    return BasicPacketFabricator()


@pytest.fixture
def sent_packets(monkeypatch):
    packets = []

    def fake_send(packet, verbose=False):
        packets.append(packet)

    monkeypatch.setattr(
        "plugins.home.PacketFabricator.send",
        fake_send
    )

    return packets


# ── tcp ───────────────────────────────────────────────

def test_tcp_packet_sent(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        protocol="TCP"
    )

    assert result is True
    assert len(sent_packets) == 1

    pkt = sent_packets[0]

    assert pkt.haslayer(TCP)
    assert pkt[TCP].dport == 80


def test_tcp_custom_payload(fabricator, sent_packets):
    fabricator.fabricate_and_send(
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocol="TCP",
        payload="CUSTOM_PAYLOAD"
    )

    pkt = sent_packets[0]

    assert b"CUSTOM_PAYLOAD" in bytes(pkt)


# ── udp ───────────────────────────────────────────────

def test_udp_packet_sent(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        protocol="UDP"
    )

    assert result is True
    assert len(sent_packets) == 1

    pkt = sent_packets[0]

    assert pkt.haslayer(UDP)
    assert pkt[UDP].dport == 53


# ── icmp ──────────────────────────────────────────────

def test_icmp_packet_sent(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        protocol="ICMP"
    )

    assert result is True
    assert len(sent_packets) == 1

    pkt = sent_packets[0]

    assert pkt.haslayer(ICMP)


# ── ftp ───────────────────────────────────────────────

def test_ftp_packet_sent(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        protocol="FTP"
    )

    assert result is True

    pkt = sent_packets[0]

    assert pkt.haslayer(TCP)
    assert pkt[TCP].dport == 21


# ── http ──────────────────────────────────────────────

def test_http_packet_sent(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        protocol="HTTP"
    )

    assert result is True

    pkt = sent_packets[0]

    assert pkt.haslayer(TCP)
    assert pkt[TCP].dport == 80


# ── https ─────────────────────────────────────────────

def test_https_packet_sent(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        protocol="HTTPS"
    )

    assert result is True

    pkt = sent_packets[0]

    assert pkt.haslayer(TCP)
    assert pkt[TCP].dport == 443


# ── dns ───────────────────────────────────────────────

def test_dns_packet_sent(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        protocol="DNS",
        payload="google.com"
    )

    assert result is True

    pkt = sent_packets[0]

    assert pkt.haslayer(DNS)
    assert pkt.haslayer(UDP)
    assert pkt[UDP].dport == 53


def test_dns_query_name(fabricator, sent_packets):
    fabricator.fabricate_and_send(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        protocol="DNS",
        payload="example.com"
    )

    pkt = sent_packets[0]

    assert pkt[DNS].qd.qname == b"example.com."


# ── unsupported protocol ──────────────────────────────

def test_unsupported_protocol_returns_false(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocol="FAKE_PROTOCOL"
    )

    assert result is False
    assert len(sent_packets) == 0


# ── exception handling ────────────────────────────────

def test_invalid_ip_returns_false(fabricator, sent_packets):
    result = fabricator.fabricate_and_send(
        src_ip="NOT_AN_IP",
        dst_ip="8.8.8.8",
        protocol="TCP"
    )

    assert result is False


def test_send_failure_returns_false(monkeypatch, fabricator):
    def fake_send(*args, **kwargs):
        raise Exception("send failed")

    monkeypatch.setattr(
        "plugins.home.PacketFabricator.send",
        fake_send
    )

    result = fabricator.fabricate_and_send(
        src_ip="1.1.1.1",
        dst_ip="8.8.8.8",
        protocol="TCP"
    )

    assert result is False