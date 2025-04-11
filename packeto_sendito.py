from scapy.all import IP, TCP, send

# Craft a packet with spoofed source IP
packet = IP(src="203.0.113.42", dst="192.168.0.129") / TCP(sport=1234, dport=80, flags="S")
send(packet, count=5)  # Source IP will appear as 10.0.0.100