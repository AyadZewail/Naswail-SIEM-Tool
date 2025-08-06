from datetime import datetime
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS
from scapy.layers.l2 import Ether
from core.interfaces import INetworkActivityAnalyzer
from models.network_activity import NetworkActivity

class NetworkActivityAnalyzer(INetworkActivityAnalyzer):
    def extract_activities(self, packets: list) -> list:
        activities = []

        for packet in packets:
            try:
                packet_time = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")
                mac_src = packet[Ether].src if packet.haslayer(Ether) else "N/A"
                activity = None

                if packet.haslayer(HTTPRequest):
                    host = packet[HTTPRequest].Host.decode(errors='ignore') if packet[HTTPRequest].Host else "Unknown"
                    path = packet[HTTPRequest].Path.decode(errors='ignore') if packet[HTTPRequest].Path else "Unknown"
                    activity = f"{packet_time} | HTTP Request: {host}{path}"

                elif packet.haslayer(DNS) and packet[DNS].qr == 0:
                    domain = packet[DNS].qd.qname.decode(errors='ignore') if packet[DNS].qd and packet[DNS].qd.qname else "Unknown"
                    activity = f"{packet_time} | DNS Query: {domain}"

                if activity:
                    entry = NetworkActivity()
                    entry.activity = activity
                    entry.mac_of_device = mac_src
                    activities.append(entry)

            except Exception as e:
                print(f"[NetworkActivityAnalyzer] Error analyzing packet: {e}")
                continue

        return activities