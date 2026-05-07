import os
import sys
import pytest
from scapy.utils import rdpcap

from plugins.home.PacketsExporter import BasicPacketExporter


# portable relative path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_PATH = os.path.join(BASE_DIR, "testingPackets.pcap")


@pytest.fixture(scope="module")
def exporter():
    return BasicPacketExporter()


@pytest.fixture(scope="module")
def packets():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")

    pkts = rdpcap(PCAP_PATH)

    if len(pkts) == 0:
        pytest.skip("pcap contains no packets")

    return pkts


# ── successful export ─────────────────────────────────

def test_export_returns_true(exporter, packets, tmp_path):
    export_path = tmp_path / "exported_packets.pcap"

    result = exporter.export(packets, str(export_path))

    assert result is True


def test_export_creates_file(exporter, packets, tmp_path):
    export_path = tmp_path / "exported_packets.pcap"

    exporter.export(packets, str(export_path))

    assert export_path.exists()


def test_exported_file_not_empty(exporter, packets, tmp_path):
    export_path = tmp_path / "exported_packets.pcap"

    exporter.export(packets, str(export_path))

    assert export_path.stat().st_size > 0


def test_exported_packet_count_matches(exporter, packets, tmp_path):
    export_path = tmp_path / "exported_packets.pcap"

    exporter.export(packets, str(export_path))

    loaded_packets = rdpcap(str(export_path))

    assert len(loaded_packets) == len(packets)


# ── empty packet list ─────────────────────────────────

def test_export_empty_packet_list(exporter, tmp_path):
    export_path = tmp_path / "empty_export.pcap"

    result = exporter.export([], str(export_path))

    assert result is True
    assert export_path.exists()


# ── invalid path handling ─────────────────────────────

def test_invalid_path_returns_false(exporter, packets):
    invalid_path = "Z:/this/path/does/not/exist/output.pcap"

    result = exporter.export(packets, invalid_path)

    assert result is False


# ── invalid packet input ──────────────────────────────

def test_invalid_packets_returns_false(exporter, tmp_path):
    export_path = tmp_path / "bad_export.pcap"

    result = exporter.export(None, str(export_path))

    assert result is False


def test_non_packet_objects_return_false(exporter, tmp_path):
    export_path = tmp_path / "bad_export.pcap"

    result = exporter.export(
        ["not", "real", "packets"],
        str(export_path)
    )

    assert result is False