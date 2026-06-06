"""Queue saturation and memory behavior under packet accumulation."""

from __future__ import annotations

import pytest

from tests.performance.helpers import (
    drain_process_queue,
    make_synthetic_packets,
    perf_metrics,
    rss_mb,
    tracemalloc_diff,
)

pytestmark = pytest.mark.performance


@pytest.mark.performance
def test_queue_caps_at_maxlen_under_overflow(headless_home_controller, perf_thresholds):
    """Enqueue more than 15k packets; qued_packets must stay at maxlen."""
    controller = headless_home_controller
    overflow_count = max(20_000, perf_thresholds["packet_count_large"] + 5_000)
    packets = make_synthetic_packets(overflow_count)

    batches = [packets[i : i + 150] for i in range(0, len(packets), 150)]
    for batch in batches:
        controller.put_packet_in_queue(batch)

    assert len(controller.qued_packets) <= 15000
    assert len(controller.qued_packets) == 15000


@pytest.mark.performance
def test_memory_under_queue_saturation_and_drain(
    headless_home_controller, perf_thresholds
):
    """RSS should stay within soft limit after saturating and draining the queue."""
    controller = headless_home_controller
    packets = make_synthetic_packets(perf_thresholds["packet_count_large"])

    rss_empty = rss_mb()
    for i in range(0, len(packets), 150):
        controller.put_packet_in_queue(packets[i : i + 150])
    rss_saturated = rss_mb()

    assert len(controller.qued_packets) <= 15000

    drain_limit = perf_thresholds["packet_count_drain"]
    with perf_metrics("queue_memory_drain") as metrics:
        drain_process_queue(controller, max_packets=drain_limit)
    rss_after_drain = rss_mb()

    metrics.record(
        rss_mb_empty=round(rss_empty, 2),
        rss_mb_saturated=round(rss_saturated, 2),
        rss_mb_after_drain=round(rss_after_drain, 2),
        queue_length_after=len(controller.qued_packets),
        packets_stored=len(controller.packets),
        time_series_entries=len(controller.time_series),
    )

    assert len(controller.packets) <= 15000
    assert rss_after_drain <= perf_thresholds["max_rss_mb"], (
        f"RSS {rss_after_drain:.1f} MB exceeds {perf_thresholds['max_rss_mb']} MB"
    )
    assert len(controller.time_series) <= perf_thresholds["max_time_series_entries"]


@pytest.mark.performance
def test_tracemalloc_queue_growth(headless_home_controller, synthetic_packets_medium):
    """Snapshot heap growth while filling the ingest queue."""
    controller = headless_home_controller

    with tracemalloc_diff("queue_extend") as diff:
        controller.put_packet_in_queue(synthetic_packets_medium)

    assert diff["delta_bytes"] >= 0
