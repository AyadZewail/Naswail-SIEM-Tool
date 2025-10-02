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


