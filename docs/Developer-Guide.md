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

Admin/Snort Integration

- The admin command for Snort is in `Code_Main.py::run_command_as_admin`. Adjust interface `-i` index and paths.


