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


