from core.interfaces import IPacketStatistics
from statistics import mean, mode, stdev
from typing import List, Any

class BasicPacketStatistics(IPacketStatistics):
    def analyze(self, packets: List[Any], totals: dict, app_proto_counts: dict) -> List[str]:
        try:
            total_packets = len(packets)

            stats = {
                "total": total_packets,
                "tcp": totals.get("tcp", 0),
                "udp": totals.get("udp", 0),
                "icmp": totals.get("icmp", 0),
                "dns": app_proto_counts.get("dns", 0),
                "http": app_proto_counts.get("http", 0),
                "https": app_proto_counts.get("https", 0),
                "telnet": app_proto_counts.get("telnet", 0),
                "ftp": app_proto_counts.get("ftp", 0),
            }

            values = list(stats.values())[1:]  # exclude 'total'
            packet_mean = mean(values)
            packet_range = max(values) - min(values)
            packet_mode = mode(values) if len(set(values)) > 1 else "No Mode"
            packet_stdev = stdev(values) if len(values) > 1 else 0

            return [
                f"Total Packets: {stats['total']}",
                f"TCP Packets: {stats['tcp']}",
                f"UDP Packets: {stats['udp']}",
                f"ICMP Packets: {stats['icmp']}",
                f"DNS Packets: {stats['dns']}",
                f"HTTP Packets: {stats['http']}",
                f"HTTPS Packets: {stats['https']}",
                f"Telnet Packets: {stats['telnet']}",
                f"FTP Packets: {stats['ftp']}",
                "Statistical Metrics:",
                f"Mean: {packet_mean:.2f}",
                f"Range: {packet_range}",
                f"Mode: {packet_mode}",
                f"Standard Deviation: {packet_stdev:.2f}",
            ]

        except Exception as e:
            print(f"[BasicPacketStatistics] Error analyzing stats: {e}")
            return ["Error generating statistics."]
