from core.interfaces import IProtocolExtractor

class BasicProtocolExtractor(IProtocolExtractor):
    HTTP_PORTS  = {80, 8080, 8888, 5988, 8000, 3000}
    HTTPS_PORTS = {443, 8443, 9443, 5989}
    SSH_PORTS   = {22}
    SMTP_PORTS  = {25, 587}
    FTP_PORTS   = {20, 21}
    TELNET_PORTS= {23}
    DNS_PORTS   = {53}
    DHCP_PORTS  = {67, 68}
    IMAP_PORTS  = {143}
    POP3_PORTS  = {110}
    RDP_PORTS   = {3389}
    NTP_PORTS   = {123}

    def extract_protocol(self, packet):
        try:
            sport = getattr(packet, 'sport', None)
            dport = getattr(packet, 'dport', None)

            # Port-based quick checks
            if sport in self.HTTP_PORTS or dport in self.HTTP_PORTS:
                return "http"
            if sport in self.HTTPS_PORTS or dport in self.HTTPS_PORTS:
                return "https"
            if sport in self.SSH_PORTS or dport in self.SSH_PORTS:
                return "ssh"
            if sport in self.SMTP_PORTS or dport in self.SMTP_PORTS:
                return "smtp"
            if sport in self.IMAP_PORTS or dport in self.IMAP_PORTS:
                return "imap"
            if sport in self.POP3_PORTS or dport in self.POP3_PORTS:
                return "pop3"
            if sport in self.RDP_PORTS or dport in self.RDP_PORTS:
                return "rdp"

            # Transport-layer detection
            if packet.haslayer("TCP"):
                return "tcp"
            if packet.haslayer("UDP"):
                # DNS / DHCP
                if sport in self.DNS_PORTS or dport in self.DNS_PORTS:
                    return "dns"
                if sport in self.DHCP_PORTS or dport in self.DHCP_PORTS:
                    return "dhcp"
                if sport in self.NTP_PORTS or dport in self.NTP_PORTS:
                    return "ntp"
                return "udp"

            # Network-layer protocol fallback
            if packet.haslayer("ICMP"):
                return "icmp"
            if packet.haslayer("IP"):
                ip_proto = packet["IP"].proto
                return {6:"tcp",17:"udp",1:"icmp"}.get(ip_proto, "other")

            return "other"
        except Exception as e:
            print(f"[BasicProtocolExtractor] Error getting protocol: {e}")
            return "unknown"
