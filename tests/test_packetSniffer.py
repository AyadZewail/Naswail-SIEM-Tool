import os
import pytest
import pandas as pd
from scapy.utils import rdpcap

from plugins.home.PacketSniffer import PacketSnifferThread


# portable relative paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_PATH = os.path.join(BASE_DIR, "testingPackets.pcap")


@pytest.fixture
def sniffer():
    return PacketSnifferThread()


@pytest.fixture(scope="module")
def packets():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")

    pkts = rdpcap(PCAP_PATH)

    if len(pkts) == 0:
        pytest.skip("pcap contains no packets")

    return pkts


# ── basic state tests ─────────────────────────────────

def test_initial_state(sniffer):
    assert sniffer.is_running() is False
    assert sniffer._source_type is None
    assert sniffer._source_value is None


def test_set_source(sniffer):
    sniffer.set_source("pcap", "abc.pcap")

    assert sniffer._source_type == "pcap"
    assert sniffer._source_value == "abc.pcap"


# ── packet batching ───────────────────────────────────

def test_emit_packet_adds_to_batch(sniffer, packets):
    sniffer._emit_packet(packets[0])

    assert len(sniffer._packet_batch) == 1


def test_flush_batch_clears_batch(sniffer, packets):
    sniffer._emit_packet(packets[0])

    assert len(sniffer._packet_batch) == 1

    sniffer._flush_batch()

    assert len(sniffer._packet_batch) == 0


# ── pcap source ───────────────────────────────────────

def test_pcap_run_processes_packets(sniffer, packets):
    captured = []

    def capture(batch):
        captured.extend(batch)

    sniffer.packet_captured.connect(capture)

    sniffer.set_source("pcap", PCAP_PATH)

    # manually enable running
    sniffer._running = True

    # direct run call avoids thread complications
    sniffer.run()

    assert len(captured) > 0


def test_pcap_run_stops_running_flag(sniffer):
    sniffer.set_source("pcap", PCAP_PATH)

    sniffer._running = True

    sniffer.run()

    assert sniffer.is_running() is False


# ── csv source ────────────────────────────────────────

def test_csv_run_processes_rows(sniffer, tmp_path):
    captured = []

    def capture(batch):
        captured.extend(batch)

    sniffer.packet_captured.connect(capture)

    csv_path = tmp_path / "test.csv"

    df = pd.DataFrame([
        {"a": 1, "b": 2},
        {"a": 3, "b": 4},
    ])

    df.to_csv(csv_path, index=False)

    sniffer.set_source("csv", str(csv_path))

    sniffer._running = True

    sniffer.run()

    assert len(captured) == 2


# ── invalid source ────────────────────────────────────

def test_invalid_source_type(sniffer):
    sniffer.set_source("INVALID", "whatever")

    sniffer._running = True

    # should not crash
    sniffer.run()

    assert sniffer.is_running() is False


# ── no source set ─────────────────────────────────────

def test_run_without_source_raises(sniffer):
    with pytest.raises(RuntimeError):
        sniffer.run()


# ── stop behavior ─────────────────────────────────────

def test_stop_sets_running_false(sniffer):
    sniffer._running = True

    sniffer.stop()

    assert sniffer.is_running() is False


# ── batch size behavior ───────────────────────────────

def test_batch_auto_flush(sniffer, packets):
    emitted_batches = []

    def capture(batch):
        emitted_batches.append(batch)

    sniffer.packet_captured.connect(capture)

    # feed 150 packets manually
    for i in range(150):
        sniffer._emit_packet(packets[i % len(packets)])

    assert len(emitted_batches) == 1
    assert len(emitted_batches[0]) == 150


# ── bad pcap path ─────────────────────────────────────

def test_invalid_pcap_path(sniffer):
    sniffer.set_source("pcap", "does_not_exist.pcap")

    sniffer._running = True

    # should not crash
    sniffer.run()

    assert sniffer.is_running() is False