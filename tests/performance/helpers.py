"""Helpers for performance tests: timed runs, metrics, synthetic traffic."""

from __future__ import annotations

import json
import os
import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Generator, Iterable, List

import psutil
from scapy.all import IP, TCP, Ether, wrpcap

REPORTS_DIR = Path(__file__).resolve().parent / "reports"
LATEST_REPORT = REPORTS_DIR / "latest.json"


def perf_duration_seconds() -> float:
    return float(os.environ.get("PERF_DURATION_SECONDS", "60"))


def perf_microbench_seconds() -> float:
    return float(os.environ.get("PERF_MICROBENCH_SECONDS", "5"))


def perf_test_timeout_seconds() -> int:
    """Hard pytest cap: duration + small buffer (never wait for pytest 300s)."""
    return int(os.environ.get("PERF_TEST_TIMEOUT", str(int(perf_duration_seconds()) + 15)))


@dataclass
class TimedRunResult:
    """Result of a fixed-duration benchmark window."""

    duration_seconds: float
    iterations: int
    cpu_samples: List[float] = field(default_factory=list)
    wall_elapsed: float = 0.0

    @property
    def iterations_per_second(self) -> float:
        if self.wall_elapsed <= 0:
            return 0.0
        return self.iterations / self.wall_elapsed

    def cpu_stats(self) -> dict[str, float]:
        if not self.cpu_samples:
            return {"mean": 0.0, "p95": 0.0, "max": 0.0}
        sorted_vals = sorted(self.cpu_samples)
        p95_idx = max(0, int(len(sorted_vals) * 0.95) - 1)
        return {
            "mean": sum(self.cpu_samples) / len(self.cpu_samples),
            "p95": sorted_vals[p95_idx],
            "max": max(self.cpu_samples),
        }


def run_for_seconds(
    work_fn: Callable[[], None],
    duration_seconds: float,
    *,
    cpu_sample_interval: float = 1.0,
) -> TimedRunResult:
    """
    Run work_fn repeatedly until duration_seconds elapses. Never runs longer
    than duration_seconds (+ negligible loop overhead).
    """
    proc = psutil.Process(os.getpid())
    proc.cpu_percent(interval=None)

    deadline = time.perf_counter() + duration_seconds
    iterations = 0
    cpu_samples: List[float] = []
    last_cpu_sample = time.perf_counter()
    start = time.perf_counter()

    while time.perf_counter() < deadline:
        work_fn()
        iterations += 1
        now = time.perf_counter()
        if now - last_cpu_sample >= cpu_sample_interval:
            cpu_samples.append(proc.cpu_percent(interval=None))
            last_cpu_sample = now

    wall = time.perf_counter() - start
    return TimedRunResult(
        duration_seconds=duration_seconds,
        iterations=iterations,
        cpu_samples=cpu_samples,
        wall_elapsed=wall,
    )


def assert_completed_within(duration_seconds: float, wall_elapsed: float, slack: float | None = None) -> None:
    """Allow overrun when each work unit can exceed the sample interval (slow process_packet)."""
    if slack is None:
        slack = max(5.0, duration_seconds * 0.5)
    assert wall_elapsed <= duration_seconds + slack, (
        f"Benchmark ran {wall_elapsed:.1f}s, expected at most {duration_seconds + slack:.1f}s"
    )


def rss_mb() -> float:
    return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)


def make_synthetic_packets(
    count: int,
    *,
    base_src: str = "10.0.0.1",
    base_dst: str = "10.0.0.2",
    base_port: int = 40000,
) -> list:
    packets = []
    for i in range(count):
        sport = base_port + (i % 20000)
        dport = 80 + (i % 1000)
        pkt = (
            Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:02")
            / IP(src=base_src, dst=base_dst)
            / TCP(sport=sport, dport=dport)
        )
        pkt.time = float(i)
        packets.append(pkt)
    return packets


def write_pcap(path: Path, packets: Iterable) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Avoid Scapy ARP/MAC resolution when serializing (can hang on Windows).
    import scapy.config

    conf = scapy.config.conf
    old_resolve = conf.neighbor.resolve
    conf.neighbor.resolve = lambda *_a, **_k: None
    try:
        wrpcap(str(path), list(packets))
    finally:
        conf.neighbor.resolve = old_resolve
    return path


class PerfMetrics:
    def __init__(self, test_name: str):
        self.test_name = test_name
        self.data: dict[str, Any] = {
            "test": test_name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "metrics": {},
        }
        self._start = 0.0
        self._rss_start = 0.0

    def start(self) -> None:
        self._start = time.perf_counter()
        self._rss_start = rss_mb()

    def stop(self) -> float:
        elapsed = time.perf_counter() - self._start
        self.data["metrics"]["elapsed_seconds"] = round(elapsed, 3)
        self.data["metrics"]["rss_mb_start"] = round(self._rss_start, 2)
        self.data["metrics"]["rss_mb_end"] = round(rss_mb(), 2)
        return elapsed

    def record(self, **kwargs: Any) -> None:
        self.data["metrics"].update(kwargs)

    def write_report(self) -> Path:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        with open(LATEST_REPORT, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        per_test = REPORTS_DIR / f"{self.test_name}.json"
        with open(per_test, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        return LATEST_REPORT


@contextmanager
def perf_metrics(test_name: str) -> Generator[PerfMetrics, None, None]:
    metrics = PerfMetrics(test_name)
    metrics.start()
    try:
        yield metrics
    finally:
        metrics.stop()
        metrics.write_report()


def drain_process_queue(controller, max_packets: int) -> int:
    """Process at most max_packets (never unbounded)."""
    calls = 0
    while calls < max_packets and controller.process_packet_index < len(controller.qued_packets):
        controller.flag_process_packet = False
        before = controller.packet_stats.get("total", 0)
        controller.process_packet()
        controller.flag_process_packet = False
        calls += 1
        if controller.packet_stats.get("total", 0) == before:
            break
    return calls


@contextmanager
def tracemalloc_diff(label: str) -> Generator[dict[str, Any], None, None]:
    tracemalloc.start()
    snap_before = tracemalloc.take_snapshot()
    result: dict[str, Any] = {"label": label, "delta_bytes": 0}
    try:
        yield result
    finally:
        snap_after = tracemalloc.take_snapshot()
        stats = snap_after.compare_to(snap_before, "lineno")
        result["delta_bytes"] = sum(s.size_diff for s in stats[:20])
        tracemalloc.stop()
