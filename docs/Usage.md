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


