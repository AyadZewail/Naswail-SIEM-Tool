"""Throughput tests with explicit time budgets (no unbounded drain)."""

from __future__ import annotations

import time

import pytest

from tests.performance.helpers import (
    assert_completed_within,
    perf_duration_seconds,
    perf_metrics,
    run_for_seconds,
)

pytestmark = pytest.mark.performance


@pytest.mark.performance
@pytest.mark.timeout(20)
def test_timer_accurate_processing_pps(
    headless_home_controller, synthetic_packets_medium, perf_thresholds, qapp
):
    """Production-like: tick every 500ms for a fixed 3s window (~2 pkt/s)."""
    controller = headless_home_controller
    controller.qued_packets.extend(synthetic_packets_medium)
    controller.process_packet_index = 0
    controller.pcap_process_packet_index = 0
    initial_total = controller.packet_stats["total"]

    duration = 3.0
    with perf_metrics("processing_timer_accurate") as metrics:
        start = time.perf_counter()
        while time.perf_counter() - start < duration:
            controller.tick()
            qapp.processEvents()
            time.sleep(0.5)
        wall = time.perf_counter() - start

    processed = controller.packet_stats["total"] - initial_total
    pps = processed / wall if wall > 0 else 0.0
    metrics.record(packets_processed=processed, processing_pps=round(pps, 2), duration_seconds=round(wall, 2))

    assert_completed_within(duration, wall)
    assert processed >= 4
    assert pps >= perf_thresholds["min_timer_process_pps"]
    assert pps <= 4.5


@pytest.mark.performance
@pytest.mark.timeout(45)
def test_max_pipeline_processing_pps(headless_home_controller, synthetic_packets_drain, perf_thresholds):
    """Max pipeline throughput measured over a fixed 20s window (not full queue drain)."""
    duration = 20.0
    controller = headless_home_controller
    packets = synthetic_packets_drain
    controller.qued_packets.extend(packets)
    controller.process_packet_index = 0
    controller.pcap_process_packet_index = 0
    initial_total = controller.packet_stats["total"]
    idx = 0
    n = max(len(packets), 1)

    def work():
        nonlocal idx
        if controller.process_packet_index >= len(controller.qued_packets):
            controller.qued_packets.append(packets[idx % n])
            controller.process_packet_index = len(controller.qued_packets) - 1
        controller.flag_process_packet = False
        controller.process_packet()
        controller.flag_process_packet = False
        idx += 1

    with perf_metrics("processing_max_pipeline") as metrics:
        result = run_for_seconds(work, duration, cpu_sample_interval=2.0)
        delta = controller.packet_stats["total"] - initial_total

    pps = delta / result.wall_elapsed if result.wall_elapsed > 0 else 0.0
    metrics.record(
        configured_duration_seconds=duration,
        packets_processed=delta,
        processing_pps=round(pps, 2),
        iterations=result.iterations,
    )

    assert_completed_within(duration, result.wall_elapsed)
    assert delta > 0
    assert pps >= perf_thresholds["min_process_pps"]
