from core.interfaces import IPacketFabricator
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, send

class BasicPacketFabricator(IPacketFabricator):
    def fabricate_and_send(self, src_ip: str, dst_ip: str, protocol: str, payload: str = "") -> bool:
        try:
            ip_layer = IP(src=src_ip, dst=dst_ip)

            if protocol == "TCP":
                transport_layer = TCP(dport=80)
                packet = ip_layer / transport_layer / (payload or "Hello TCP")

            elif protocol == "UDP":
                transport_layer = UDP(dport=53)
                packet = ip_layer / transport_layer / (payload or "Hello UDP")

            elif protocol == "ICMP":
                packet = ip_layer / ICMP() / (payload or "Hello ICMP")

            elif protocol == "FTP":
                transport_layer = TCP(dport=21)
                packet = ip_layer / transport_layer / (payload or "FTP Packet")

            elif protocol == "HTTP":
                transport_layer = TCP(dport=80)
                packet = ip_layer / transport_layer / (payload or "HTTP Packet")

            elif protocol == "HTTPS":
                transport_layer = TCP(dport=443)
                packet = ip_layer / transport_layer / (payload or "HTTPS Packet")

            elif protocol == "DNS":
                packet = ip_layer / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=payload or "example.com"))

            else:
                print(f"[Fabricator] Unsupported protocol: {protocol}")
                return False

            send(packet, verbose=False)
            return True

        except Exception as e:
            print(f"[Fabricator] Error crafting/sending packet: {e}")
            return False