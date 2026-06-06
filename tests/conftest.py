"""Shared pytest fixtures for unit, integration, and performance tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
GENERATED_DIR = FIXTURES_DIR / "generated"
REPORTS_DIR = TESTS_DIR / "performance" / "reports"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return float(raw)


@pytest.fixture(scope="session")
def perf_thresholds() -> dict:
    """Environment-tunable soft thresholds for performance tests."""
    duration = _env_int("PERF_DURATION_SECONDS", 60)
    return {
        "duration_seconds": duration,
        "microbench_seconds": _env_int("PERF_MICROBENCH_SECONDS", 5),
        "test_timeout_seconds": _env_int("PERF_TEST_TIMEOUT", duration + 45),
        "min_ingest_pps": _env_int("PERF_MIN_INGEST_PPS", 200),
        "min_process_pps": _env_int("PERF_MIN_PROCESS_PPS", 10),
        "min_timer_process_pps": _env_float("PERF_MIN_TIMER_PROCESS_PPS", 1.5),
        "max_rss_mb": _env_int("PERF_MAX_RSS_MB", 2000),
        "max_cpu_percent": _env_float("PERF_MAX_CPU_PERCENT", 110.0),
        "soak_seconds": _env_int("PERF_SOAK_SECONDS", 60),
        "packet_count_small": _env_int("PERF_PACKET_COUNT_SMALL", 1000),
        "packet_count_medium": _env_int("PERF_PACKET_COUNT_MEDIUM", 500),
        "packet_count_large": _env_int("PERF_PACKET_COUNT_LARGE", 5000),
        "packet_count_drain": _env_int("PERF_PACKET_COUNT_DRAIN", 200),
        "max_time_series_entries": _env_int("PERF_MAX_TIME_SERIES_ENTRIES", 20000),
        "soak_rss_growth_ratio": _env_float("PERF_SOAK_RSS_GROWTH_RATIO", 1.25),
    }


@pytest.fixture(scope="session", autouse=True)
def _ensure_perf_dirs() -> None:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
