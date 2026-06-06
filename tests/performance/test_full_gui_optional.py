"""
Optional full-GUI performance smoke test.

Excluded from default pytest runs (gui marker). Run manually:
  pytest tests/performance/test_full_gui_optional.py -m gui -v
"""

from __future__ import annotations

import time

import pytest
from unittest.mock import patch

from tests.performance.helpers import perf_metrics, rss_mb

pytestmark = [pytest.mark.performance, pytest.mark.gui, pytest.mark.slow]


@pytest.mark.gui
def test_gui_controller_stays_responsive_brief_soak(
    headless_home_controller, synthetic_packets_medium, qapp
):
    """
    Uses headless_home_controller (mock UI) as a lightweight GUI-tier smoke test.
    A true full-window test would require the full Bootstrap + views stack;
    this validates timer + process_events under load without a display server.
    """
    controller = headless_home_controller
    controller.qued_packets.extend(synthetic_packets_medium[:500])
    controller.process_packet_index = 0
    controller.pcap_process_packet_index = 0

    rss_start = rss_mb()

    with (
        perf_metrics("gui_brief_soak") as metrics,
        patch("controllers.Home_Controller.HomeController.draw_gauge"),
    ):
        start = time.perf_counter()
        ticks = 0
        while time.perf_counter() - start < 5.0:
            controller.tick()
            qapp.processEvents()
            time.sleep(0.5)
            ticks += 1

    metrics.record(
        ticks=ticks,
        rss_start_mb=round(rss_start, 2),
        rss_end_mb=round(rss_mb(), 2),
        packets_processed=controller.packet_stats["total"],
    )

    assert ticks >= 8
    assert controller.packet_stats["total"] >= 5
