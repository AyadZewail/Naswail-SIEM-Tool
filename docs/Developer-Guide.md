Developer Guide

Project Conventions

- Python 3.13, Windows-first
- PyQt6 UI in `views/`, logic in `Code_*.py`
- Services registered in `core/di.py` and retrieved by key

Extending with Plugins

1) Create a module under `plugins/<domain>/` implementing a `core/interfaces.py` contract.
2) Register the implementation in `core/di.py` as a singleton.
3) Wire the service into the relevant window in `Code_*.py`.

Example: Adding a new analyzer

- Implement `INetworkActivityAnalyzer` in `plugins/tools/MyAnalyzer.py`.
- Register in `core/di.py`:

container.register_singleton("network_activity_analyzer", MyAnalyzer())

- Use it in the Tools window to populate UI tables.

Autopilot & TI

- `AutopilotEngine` calls a remote endpoint defined in `core/di.py`. Update the ngrok/base URL as needed.
- Add additional searchers under `plugins/incident_response/scrapers/` and include them in the `ThreatIntelligence` registration.

Testing Tips

- Use `data/packet_file*.pcap` to simulate traffic without live capture.
- Ensure `resources/` artifacts exist; mock when running unit tests.

Performance Testing

Performance tests live under `tests/performance/` and use synthetic Scapy PCAPs generated at `tests/fixtures/generated/` (gitignored).

```bash
pip install -r requirements-dev.txt

# Default CI-friendly run (excludes soak and gui)
pytest tests/performance -m performance -v

# Tune soft thresholds on slower hardware (Windows PowerShell)
$env:PERF_MIN_PROCESS_PPS="20"
$env:PERF_MAX_RSS_MB="1200"
pytest tests/performance -v

# Extended soak (60s default; set PERF_SOAK_SECONDS=1800 for 30 min)
pytest tests/performance -m soak -v

# Optional GUI-tier smoke
pytest tests/performance/test_full_gui_optional.py -m gui -v
```

Environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `PERF_DURATION_SECONDS` | 60 | **CPU under load:** fixed run length (then stop and log) |
| `PERF_MICROBENCH_SECONDS` | 5 | Plugin micro-benchmark window |
| `PERF_TEST_TIMEOUT` | duration + 15 | Hard pytest kill (never wait forever) |
| `PERF_MIN_INGEST_PPS` | 200 | Minimum enqueue / sniffer ingest rate |
| `PERF_MIN_PROCESS_PPS` | 30 | Minimum headless `process_packet` drain rate |
| `PERF_MIN_TIMER_PROCESS_PPS` | 1.5 | Minimum rate with 500ms `tick()` (expect ~2) |
| `PERF_MAX_RSS_MB` | 1024 | Max resident memory after queue drain |
| `PERF_MAX_CPU_PERCENT` | 90 | Max mean process CPU during burst |
| `PERF_SOAK_SECONDS` | 60 | Soak test duration |
| `PERF_PACKET_COUNT_SMALL` | 1000 | Synthetic packet count (small fixture) |

Reports are written to `tests/performance/reports/latest.json`. The production pipeline processes about **2 packets/s** via `QTimer` (500ms tick) while ingest can be much higher; queues cap at **15000** packets (`core/di.py`).

Manual profiling: `py-spy record -o profile.svg -- python main.py` (see `profile.svg` in repo root).

Admin/Snort Integration

- The admin command for Snort is in `Code_Main.py::run_command_as_admin`. Adjust interface `-i` index and paths.



