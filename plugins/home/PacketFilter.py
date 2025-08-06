# plugins/analysis/packet_filter.py
from core.interfaces import IPacketFilter
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
import ipaddress

class BasicPacketFilter(IPacketFilter):
    def __init__(self, protocol_extractor):
        self.protocol_extractor = protocol_extractor

    def is_local_ip(self,ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private  # returns True for local IPs, False for outside
        except ValueError:
    
            return False  # handle invalid IP addresses
    
    def filter_packets(self, packets: list, criteria: dict) -> list:
        filtered_packets = []

        selected_protocols = criteria.get("protocols", [])
        src_filter = criteria.get("src_ip", "")
        dst_filter = criteria.get("dst_ip", "")
        port_filter = criteria.get("port", "")
        stime = criteria.get("start_time", 946677600)
        etime = criteria.get("end_time", 946677600)
        direction = criteria.get("direction", "Any")

        for packet in packets:
            try:
                # Extract info
                has_ip = packet.haslayer(IP)
                src_ip = packet[IP].src if has_ip else "N/A"
                dst_ip = packet[IP].dst if has_ip else "N/A"
                has_tcp = packet.haslayer(TCP)
                has_udp = packet.haslayer(UDP)
                has_icmp = packet.haslayer(ICMP)
                timestamp = float(packet.time)
                proto = self.protocol_extractor.extract_protocol(packet)
                layer = (
                    "udp" if has_udp else
                    "tcp" if has_tcp else
                    "icmp" if has_icmp else "N/A"
                )

                # Extract ports
                sport = dport = None
                if has_tcp:
                    sport, dport = packet[TCP].sport, packet[TCP].dport
                elif has_udp:
                    sport, dport = packet[UDP].sport, packet[UDP].dport

                # Filtering checks
                protocol_match = proto in selected_protocols if selected_protocols else True
                if "udp" in selected_protocols and layer == "udp":
                    protocol_match = True
                elif "tcp" in selected_protocols and layer == "tcp":
                    protocol_match = True
                elif "icmp" in selected_protocols and layer == "icmp":
                    protocol_match = True

                time_match = (stime == 946677600 or stime <= timestamp) and \
                             (etime == 946677600 or etime >= timestamp)

                src_match = src_filter in src_ip if src_filter else True
                dst_match = dst_filter in dst_ip if dst_filter else True

                # Inside/Outside match
                src_local = self.is_local_ip(src_ip)
                dst_local = self.is_local_ip(dst_ip)
                if direction == "Inside":
                    ip_match = src_local and dst_local
                elif direction == "Outside":
                    ip_match = not src_local or not dst_local
                else:
                    ip_match = True

                # Port match
                port_match = True
                if port_filter:
                    try:
                        port_filter = int(port_filter)
                        port_match = (sport == port_filter or dport == port_filter)
                    except ValueError:
                        port_match = False

                # Final decision
                if all([protocol_match, src_match, dst_match, ip_match, port_match, time_match]):
                    filtered_packets.append(packet)

            except Exception as e:
                print(f"[PacketFilter] Error on packet: {e}")
                continue

        return filtered_packets