"""Measure packet ingest rate into qued_packets (enqueue / sniffer path)."""

from __future__ import annotations

import time

import pytest

from plugins.home.PacketSniffer import PacketSnifferThread
from tests.performance.helpers import perf_metrics

pytestmark = pytest.mark.performance


def _batch_packets(packets: list, batch_size: int = 150) -> list[list]:
    return [packets[i : i + batch_size] for i in range(0, len(packets), batch_size)]


@pytest.mark.performance
def test_ingest_throughput_put_packet_in_queue(
    headless_home_controller, synthetic_packets_large, perf_thresholds
):
    """Enqueue via put_packet_in_queue (production ingest API)."""
    controller = headless_home_controller
    batches = _batch_packets(synthetic_packets_large)

    with perf_metrics("ingest_put_packet_in_queue") as metrics:
        start = time.perf_counter()
        total = 0
        for batch in batches:
            controller.put_packet_in_queue(batch)
            total += len(batch)
        elapsed = time.perf_counter() - start

    pps = total / elapsed if elapsed > 0 else 0.0
    metrics.record(
        packets=total,
        ingest_pps=round(pps, 2),
        queue_length=len(controller.qued_packets),
    )

    assert len(controller.qued_packets) <= 15000
    assert pps >= perf_thresholds["min_ingest_pps"], (
        f"Ingest PPS {pps:.1f} below threshold {perf_thresholds['min_ingest_pps']}"
    )


@pytest.mark.performance
def test_ingest_throughput_pcap_sniffer(generated_pcap_small, perf_thresholds):
    """PCAP replay through PacketSnifferThread (synchronous run, no QThread)."""
    sniffer = PacketSnifferThread()
    captured: list = []

    def on_batch(batch):
        captured.extend(batch)

    sniffer.packet_captured.connect(on_batch)
    sniffer.set_source("pcap", str(generated_pcap_small))
    sniffer._running = True

    with perf_metrics("ingest_pcap_sniffer") as metrics:
        start = time.perf_counter()
        sniffer.run()
        elapsed = time.perf_counter() - start

    total = len(captured)
    pps = total / elapsed if elapsed > 0 else 0.0
    metrics.record(packets=total, ingest_pps=round(pps, 2), elapsed_seconds=elapsed)

    assert total == 1000
    assert pps >= perf_thresholds["min_ingest_pps"], (
        f"PCAP sniffer ingest PPS {pps:.1f} below {perf_thresholds['min_ingest_pps']}"
    )
