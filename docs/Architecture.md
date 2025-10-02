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


