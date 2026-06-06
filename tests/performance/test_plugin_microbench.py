"""Plugin micro-benchmarks: each runs for PERF_MICROBENCH_SECONDS (default 5s) only."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from plugins.home.ErrorChecker import BasicErrorChecker
from plugins.home.PacketFilter import BasicPacketFilter
from plugins.home.ProtocolExtractor import BasicProtocolExtractor
from tests.performance.helpers import (
    assert_completed_within,
    perf_metrics,
    perf_microbench_seconds,
    run_for_seconds,
)

pytestmark = [pytest.mark.performance, pytest.mark.timeout(15)]


def _timed_microbench(name: str, work_fn, perf_thresholds, min_iterations: int = 1):
    duration = perf_thresholds["microbench_seconds"]
    with perf_metrics(name) as metrics:
        result = run_for_seconds(work_fn, duration, cpu_sample_interval=1.0)
        metrics.record(
            configured_duration_seconds=duration,
            iterations=result.iterations,
            iterations_per_second=round(result.iterations_per_second, 2),
            wall_elapsed_seconds=round(result.wall_elapsed, 2),
        )
    assert_completed_within(duration, result.wall_elapsed)
    assert result.iterations >= min_iterations
    return result


@pytest.mark.performance
def test_protocol_extractor_timed(synthetic_packets_small, perf_thresholds):
    extractor = BasicProtocolExtractor()
    packets = synthetic_packets_small
    n = len(packets)
    i = 0

    def work():
        nonlocal i
        extractor.extract_protocol(packets[i % n])
        i += 1

    _timed_microbench("micro_protocol_extractor", work, perf_thresholds, min_iterations=100)


@pytest.mark.performance
def test_error_checker_timed(synthetic_packets_small, perf_thresholds):
    checker = BasicErrorChecker(corrupted_packet_list=[], logger=[])
    packets = synthetic_packets_small
    n = len(packets)
    i = 0

    def work():
        nonlocal i
        with patch("plugins.home.ErrorChecker.raw", return_value=b""):
            checker.is_corrupted(packets[i % n])
        i += 1

    _timed_microbench("micro_error_checker", work, perf_thresholds, min_iterations=50)


@pytest.mark.performance
def test_packet_filter_timed(synthetic_packets_small, perf_thresholds):
    extractor = BasicProtocolExtractor()
    packet_filter = BasicPacketFilter(protocol_extractor=extractor)
    packets = list(synthetic_packets_small)
    criteria = {"protocols": ["tcp"]}
    ran = {"done": False}

    def work():
        if not ran["done"]:
            packet_filter.filter_packets(packets, criteria)
            ran["done"] = True

    result = _timed_microbench("micro_packet_filter", work, perf_thresholds, min_iterations=1)
    assert ran["done"]


@pytest.mark.performance
def test_snort_check_mock_timed(synthetic_packets_small, perf_thresholds):
    detector = MagicMock()
    detector.check = lambda _packet: None
    packets = synthetic_packets_small
    n = len(packets)
    i = 0

    def work():
        nonlocal i
        detector.check(packets[i % n])
        i += 1

    _timed_microbench("micro_snort_check_mock", work, perf_thresholds, min_iterations=500)
