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


