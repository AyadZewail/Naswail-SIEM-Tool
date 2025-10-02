Naswail SIEM Tool — Full Documentation

---

# docs/README.md

Naswail SIEM Tool — Documentation

This documentation set covers overview, setup, architecture, module reference, usage guides, and developer topics.

- Overview: see `Overview.md`
- Getting Started: see `Getting-Started.md`
- Architecture: see `Architecture.md`
- Module Reference: see `Module-Reference.md`
- Usage Guides: see `Usage.md`
- Developer Guide: see `Developer-Guide.md`
- FAQ: see `FAQ.md`

---

# docs/Overview.md

Overview

Naswail SIEM Tool is a Windows-focused, PyQt6 desktop application for network packet capture, analysis, visualization, and incident response. It provides:

- Real-time packet capture and PCAP import
- Packet decoding and detailed views
- Filtering by protocol/IP/port/time and sensor-aware filtering
- Statistical summaries and visualizations (charts, maps, topology)
- Geolocation mapping via MaxMind GeoLite2
- Anomaly detection using an autoencoder or Snort log integration
- Traffic forecasting and network activity extraction
- Threat intelligence aggregation (web searchers + preprocessing)
- Assisted incident response with an autopilot engine and Windows admin actions

High-Level Components

- UI Layers: `Code_Main.py` (main window and splash), `Code_Analysis.py`, `Code_Tools.py`, `Code_IncidentResponse.py` connect to designer-based views in `views/`.
- Core: Dependency injection container (`core/di.py`), interfaces (`core/interfaces.py`), plugin manager (`core/plugin_manager.py`).
- Plugins: Feature implementations under `plugins/` (home, analysis, tools, incident_response).
- Models: Data structures under `models/`.
- Resources: ML models, scalers, geolite DB, and static assets under `resources/`.
- Data: Sample PCAPs, logs, and outputs under `data/`.

Platform & Prerequisites

- Windows (admin recommended for full features like Snort integration)
- Python 3.13 recommended
- Npcap installed
- MaxMind GeoLite2 City database present

---

# docs/Getting-Started.md

Getting Started

Prerequisites

- Windows
- Python 3.13 (ensure added to PATH)
- Npcap
- Visual Studio Code (optional, run as admin)

Install Dependencies

1) Create and activate a virtual environment (optional but recommended):

PowerShell:

py -3.13 -m venv venv
venv\Scripts\activate

2) Install Python packages:

pip install -r requirements.txt

3) Place external assets where required:

- GeoLite2: ensure resources/GeoLite2-City.mmdb exists (extract from the provided RAR if needed).
- ML artifacts referenced in core/di.py must exist under resources/.

Run the Application

PowerShell:

python Code_Main.py

Administrative Mode and Snort

- When run as Administrator, the app can launch Snort using the command in Code_Main.py (run_command_as_admin). Adjust interface index and paths as needed.

First Run Checklist

- Npcap installed
- resources/GeoLite2-City.mmdb present
- Optional: Snort installed and configured
- Load a sample PCAP from data/ or start live capture

---

# docs/Architecture.md

Architecture

Layers

- UI Layer: `Code_Main.py` orchestrates application startup with a splash screen and opens the main `Naswail` window. Feature windows are implemented in `Code_Analysis.py`, `Code_Tools.py`, and `Code_IncidentResponse.py`, each using Qt UI classes from `views/`.
- Core Layer: `core/di.py` sets up a simple service container to register and resolve singletons. `core/interfaces.py` declares contracts for packet decoding, details, statistics, filtering, anomaly detection, exporter, sensors, network activity, threat intelligence, and autopilot. `core/plugin_manager.py` provides a generic plugin discovery/loader (optional in current flow).
- Plugin Layer: Concrete implementations under `plugins/` grouped by domain: `home` (packet-centric utilities), `analysis` (geolocation), `tools` (analytics, prediction), and `incident_response` (threat intel, autopilot, net admin).
- Data & Resources: Inputs and outputs in `data/`; models and databases in `resources/` (ML models, scalers, GeoLite2 mmdb).

Dependency Injection

`core/di.py` registers singletons with explicit keys, then other modules resolve them by key. Key registrations include:

- Packet processing: `packet_decoder`, `packet_details`, `packet_statistics`, `packet_filter`, `error_checker`
- State stores: `packets`, `anomalies`, `network_log`, `blacklist`, `blocked_ports`, `time_series`
- Analytics & mapping: `network_activity_analyzer`, `regression_predictor`, `geo_mapper`
- Anomaly detection: `anomaly_detector` using `AEAnomalyDetector` with artifacts in `resources/`
- Incident response: `threat_intelligence`, `ThreatMitigationEngine` (Windows), `autopilot`

Data Flow (Typical)

1) Capture/Import: Packets enter the system via sniffer/import (handled in UI code). They are appended to the shared `packets` list.
2) Processing: `error_checker` flags corrupted packets; `protocol_extractor` and `packet_filter` enable views; `packet_details` and `packet_decoder` provide user-visible representations.
3) Analytics & Viz: `packet_statistics`, charts/plots in UI, `geo_mapper` builds a map, topology rendered in `Code_Main.py`.
4) Detection: `anomaly_detector` evaluates packets and updates `anomalies`.
5) Activity/Prediction: `network_activity_analyzer` extracts activities; `regression_predictor` forecasts traffic trends.
6) Incident Response: `ThreatIntelligence` aggregates web intel; `autopilot` suggests actions; `ThreatMitigationEngine` applies Windows network changes.

Extensibility

- Implement new features by adding a plugin under `plugins/<domain>/` and registering it in `core/di.py`.
- Add new UI controls in `views/` and wire them in the corresponding `Code_*.py` window.

---

# docs/Module-Reference.md

Module Reference

Entry Points

- Code_Main.py: PyQt6 application startup, splash screen, main `Naswail` window, optional Snort launch.
- Code_Analysis.py: Analysis window (`Window_Analysis`) for decoding, details, charts, geolocation.
- Code_Tools.py: Tools window (`Window_Tools`) for predictions and utilities.
- Code_IncidentResponse.py: Incident response GUI, controller, timers and actions.

Core

- core/interfaces.py: Contracts for packet processing, analytics, sensors, TI, autopilot.
- core/di.py: ServiceContainer registration of singletons used across the app.
- core/plugin_manager.py: Generic plugin discovery and lifecycle management.

Plugins — home

- PacketDecoder.BasicPacketDecoder: Converts packet bytes to hex+ASCII lines.
- PacketDetails.BasicPacketDetails: Extracts readable fields from packets.
- ProtocolExtractor.BasicProtocolExtractor: Deduces application protocol labels.
- ErrorChecker.BasicErrorChecker: Validates checksums, logs corrupt packets.
- PacketStatistics.BasicPacketStatistics: Summaries and distributions.
- PacketFilter.BasicPacketFilter: Filters packets by criteria.
- SensorSystem.BasicSensorSystem: Maintains MAC-addressed sensors and helpers.
- PacketsExporter.BasicPacketExporter: Writes PCAP or CSV (per implementation).
- AEAnomalyDetector.AEAnomalyDetector: Autoencoder-based anomaly detection using resources models.
- AnomalyDetector.SnortAnomalyDetector: Parses Snort alerts and maps SIDs to attack names.

Plugins — analysis

- GeoMapper.MaxMindGeoMapper: Uses `resources/GeoLite2-City.mmdb` to geolocate IPs.

Plugins — tools

- NetworkActivityAnalyzer.NetworkActivityAnalyzer: Extracts web and HTTP activities from packets.
- TrafficPredictor.BasicRegressionPredictor: Forecasts traffic with regression.

Plugins — incident_response

- scrapers.BingSearcher / YouTubeSearcher: Source-specific searchers.
- IntelPreprocessor.SimpleIntelPreprocessor: Cleans and condenses raw intel.
- ThreatIntelligence.ThreatIntelligence: Aggregates results across searchers and preprocesses them.
- network_engines.WindowsNetworkAdmin: Applies Windows firewall/netsh mitigations.
- AutopilotEngine.KaggleLLMEngine: Calls a remote LLM endpoint to decide actions.

Models

- models/network_activity.py: Structures representing detected activities.
- models/node.py: Graph/topology node data models.

Views

- views/UI_Main.py, UI_Analysis.py, UI_Tools.py, UI_IncidentResponse.py: Qt Designer generated UI classes used by `Code_*.py` windows.

---

# docs/Usage.md

Usage Guides

General

- Launch the app: `python Code_Main.py` (prefer Administrator for full features)
- Use the top-level tabs/buttons to switch between Analysis, Tools, and Incident Response.

Analysis

- Capture: Start/Stop capture from the Analysis window; import PCAP from File menu.
- Select a packet (double-click) to enable Decode and Details views.
- Filtering: Apply filters by protocol/IP/port/time; reset when switching sensor focus.
- Charts: Generate time-series, histograms, pie charts after focusing on sensors if needed.
- GeoMap: Ensure `resources/GeoLite2-City.mmdb`; expect a short delay for rendering.

Tools

- Network Activity: Run activity extraction to list visited sites/HTTP requests from current packet set.
- Traffic Prediction: Run the regression predictor; a brief compute delay is expected.

Incident Response

- Threat Intelligence: Provide query data; the aggregator will call multiple sources and preprocess results.
- Autopilot: Uses a remote LLM service to choose an action; ensure connectivity to the configured URL in `core/di.py`.
- Mitigation: Windows network admin engine can block ports/IPs via firewall or netsh; Administrator privileges required.

Data Management

- Export: Save packets via exporter functions where available.
- Logs: Review network logs and anomalies lists; corrupted packets are recorded by the error checker.

---

# docs/Developer-Guide.md

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

---

# docs/FAQ.md

FAQ

Q: The GeoMap does not render.
A: Ensure `resources/GeoLite2-City.mmdb` exists; restart after adding.

Q: Anomaly detection not working?
A: Confirm `resources/mlp_teacher.pth`, `resources/all_error.pkl`, and `resources/base_MLP_scaler.pkl` exist. Otherwise, switch to an alternative detector if provided.

Q: Snort window doesn’t open or alerts don’t appear.
A: Run as Administrator; verify Snort paths in `Code_Main.py` and correct interface index `-i`.

Q: Packet decode/details disabled.
A: Double-click a packet row/select it first; ensure packets are loaded/captured.

Q: Which Python version?
A: 3.13 is recommended by the project’s Readme; a virtual environment is suggested.


