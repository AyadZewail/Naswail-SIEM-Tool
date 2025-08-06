from core.interfaces import IAnomalyDetector
from scapy.all import IP
from threading import Thread
from collections import defaultdict
from typing import Any, Dict, Optional
from datetime import datetime
import time, re
import traceback

class SnortAnomalyDetector(IAnomalyDetector):
    def __init__(self, rules_file: str, log_file: str):
        self.snort_rules = self._load_snort_rule_names(rules_file)
        self.snort_alerts = defaultdict(list)  # {(src_ip, dst_ip): [label, ...]}
        self.thread = Thread(target=self._monitor_snort_logs, args=(log_file,), daemon=True)
        self.thread.start()
    
    def _load_snort_rule_names(self, rules_file: str) -> Dict[int, str]:
        sid_to_attack = {}
        with open(rules_file, 'r') as f:
            for line in f:
                if line.startswith("alert"):
                    sid = None
                    attack_name = "Unknown"

                    # Extract SID
                    sid_match = re.search(r"sid:", line)
                    if sid_match:
                        sid = int(line[sid_match.end():sid_match.end()+7])
                        # match = re.search(r'\b\w+\b', line[sid_match.end():])
                        # if match:
                        #     start_pos = line[:match.start()].rfind(' ') + 1
                        #     end_pos = sid_match.start() + match.end()
                        #     sid = int(line[start_pos:end_pos])

                    # Extract attack label from msg field
                    msg_match = re.search(r'msg:"', line)
                    if msg_match:
                        match = re.search(r'\b\w+\b', line[msg_match.end():])
                        if match:
                            end_pos = line[msg_match.end():].find('"')
                            attack_name = line[msg_match.end():msg_match.end() + end_pos]

                    if sid is not None:
                        sid_to_attack[sid] = attack_name  # Map SID to attack label

        return sid_to_attack

    def _monitor_snort_logs(self, log_file: str):
        with open(log_file, "r") as f:
            f.seek(0, 2)  # Move to end of file (process only new alerts)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(10)  # Avoid CPU overuse
                    continue

                try:
                    src_ip = dst_ip = sport = dport = None
                    attack_label = "Unknown"
                    # Extract SID from alert log (format: "[**] [SID:REV] Attack Name [**]")
                    sid_match = re.search(r"\[\*\*\] \[(\d+):", line)
                    if sid_match:
                        match = re.search(r'\b\w+\b', line[sid_match.end():])
                        if match:
                            end_pos = line[sid_match.end():].find(':')
                        sid = int(line[sid_match.end():sid_match.end() + end_pos])
                        if sid in self.snort_rules:
                            attack_label = self.snort_rules[sid]

                        # Extract source and destination IPs
                        ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
                        if ip_match:
                            end_space = line[ip_match.end()-1:].find(' ')
                            end_colon = line[ip_match.end()-1:].find(':')
                            end_pos = min(pos for pos in [end_space, end_colon] if pos != -1)
                            if end_pos == end_space:
                                src_ip = line[ip_match.start():ip_match.end() + end_pos - 1]
                                end_pos = line[ip_match.end() + 4:].find('\n')
                                dst_ip = line[ip_match.end() + 4:ip_match.end() + 4 + end_pos]
                            elif end_pos == end_colon:
                                src_ip = line[ip_match.start():ip_match.end() + end_pos - 1]
                                end_sport = line[ip_match.end() + end_pos + 1:].find(' ')
                                sport = line[ip_match.end() + end_pos:ip_match.end() + end_pos + end_sport + 1]
                                sdst = ip_match.end() + end_pos + end_sport + 5
                                end_pos = line[sdst:].find(':')
                                dst_ip = line[sdst:sdst + end_pos]
                                end_dport = line[sdst:].find('\n')
                                dport = line[sdst + end_pos + 1 : sdst + end_dport]

                            # Record the alert
                            self.snort_alerts[(src_ip, dst_ip)].append(attack_label)
                            
                            # Flag for whether we've added to tableWidget_4
                            added_to_table = False
                            anomaly_signature = (src_ip, dst_ip, attack_label)
                            
                            # Find all packets matching this signature and add to anomalies
                            
                except Exception as e:
                    print(f"Error processing log line: {e}")
                    tb = traceback.format_exc()
                    print("Traceback details:")
                    print(tb)
                    continue

    def check_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if (src_ip, dst_ip) in self.snort_alerts:
                    attack_name = self.snort_alerts[(src_ip, dst_ip)][0]
                    return attack_name
        except Exception as e:
            print(f"[SnortAnomalyDetector] check_packet error: {e}")
        return None