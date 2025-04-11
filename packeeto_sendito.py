from scapy.all import IP, TCP, send

packet = IP(src="203.0.113.42", dst="192.168.0.129") / TCP(sport=1234, dport=80, flags="S")
send(packet, count=5)
