"""CPU under load: fixed-duration run, sample CPU, log JSON, assert CPU threshold."""

from __future__ import annotations

import pytest

from tests.performance.helpers import (
    assert_completed_within,
    perf_duration_seconds,
    perf_metrics,
    run_for_seconds,
)

pytestmark = pytest.mark.performance


@pytest.mark.performance
def test_cpu_under_load_fixed_duration(headless_home_controller, synthetic_packets_drain, perf_thresholds):
    """
    Run process_packet load for exactly PERF_DURATION_SECONDS (default 60s).
    Sample CPU every second, write report, assert mean CPU below threshold.
    """
    duration = perf_thresholds["duration_seconds"]
    controller = headless_home_controller
    packets = synthetic_packets_drain
    controller.qued_packets.extend(packets)
    controller.process_packet_index = 0
    controller.pcap_process_packet_index = 0
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

    with perf_metrics("cpu_under_load") as metrics:
        result = run_for_seconds(work, duration, cpu_sample_interval=1.0)
        cpu = result.cpu_stats()
        metrics.record(
            configured_duration_seconds=duration,
            wall_elapsed_seconds=round(result.wall_elapsed, 2),
            iterations=result.iterations,
            iterations_per_second=round(result.iterations_per_second, 2),
            cpu_sample_count=len(result.cpu_samples),
            cpu_mean_percent=round(cpu["mean"], 2),
            cpu_p95_percent=round(cpu["p95"], 2),
            cpu_max_percent=round(cpu["max"], 2),
            cpu_samples=result.cpu_samples,
        )

    assert_completed_within(duration, result.wall_elapsed)
    assert result.iterations > 0
    assert len(result.cpu_samples) >= 1, "Expected CPU samples during the timed window"
    if cpu["p95"] > perf_thresholds["max_cpu_percent"]:
        pytest.fail(
            f"p95 CPU {cpu['p95']:.1f}% exceeds PERF_MAX_CPU_PERCENT="
            f"{perf_thresholds['max_cpu_percent']}% (set env higher if burst load is expected)"
        )
