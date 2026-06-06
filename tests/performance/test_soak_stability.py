"""Extended stability: sustained enqueue + timer-driven processing."""

from __future__ import annotations

import time

import pytest

from tests.performance.helpers import make_synthetic_packets, perf_metrics, rss_mb

pytestmark = [pytest.mark.performance, pytest.mark.soak, pytest.mark.slow]


@pytest.mark.soak
@pytest.mark.timeout(3600)
def test_soak_enqueue_and_tick_stability(
    headless_home_controller, perf_thresholds, qapp
):
    """
    Run for PERF_SOAK_SECONDS (default 60): periodic ingest + tick every 500ms.
    Assert no runaway RSS and queue stays bounded.
    """
    controller = headless_home_controller
    soak_seconds = perf_thresholds["soak_seconds"]
    batch_size = 150
    batch_packets = make_synthetic_packets(batch_size)

    rss_samples: list[float] = [rss_mb()]
    exceptions: list[str] = []
    ticks = 0

    with perf_metrics("soak_stability") as metrics:
        start = time.perf_counter()
        last_tick = start

        while time.perf_counter() - start < soak_seconds:
            try:
                now = time.perf_counter()
                if now - last_tick >= 0.5:
                    controller.tick()
                    qapp.processEvents()
                    last_tick = now
                    ticks += 1

                if ticks % 4 == 0:
                    controller.put_packet_in_queue(batch_packets)

                if ticks % 20 == 0:
                    rss_samples.append(rss_mb())

            except Exception as exc:
                exceptions.append(str(exc))
                break

            time.sleep(0.05)

        elapsed = time.perf_counter() - start

    assert not exceptions, f"Soak test raised: {exceptions}"
    assert len(controller.qued_packets) <= 15000
    assert len(controller.packets) <= 15000

    rss_growth = rss_samples[-1] / rss_samples[0] if rss_samples[0] > 0 else 1.0
    metrics.record(
        soak_seconds=round(elapsed, 1),
        ticks=ticks,
        rss_samples=len(rss_samples),
        rss_start_mb=round(rss_samples[0], 2),
        rss_end_mb=round(rss_samples[-1], 2),
        rss_growth_ratio=round(rss_growth, 3),
        queue_length=len(controller.qued_packets),
        backlog= len(controller.qued_packets) - controller.process_packet_index,
    )

    assert rss_growth <= perf_thresholds["soak_rss_growth_ratio"], (
        f"RSS grew {rss_growth:.2f}x over soak (limit {perf_thresholds['soak_rss_growth_ratio']})"
    )
