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


