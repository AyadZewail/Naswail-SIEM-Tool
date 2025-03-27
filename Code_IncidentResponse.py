import sys
import numpy as np
import pandas as pd
import psutil
import os
import platform
import subprocess
import ipaddress
from PyQt6 import uic
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import QPainter, QPixmap
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import Ether
import base64
import urllib.parse
import binascii
import gzip
import codecs
from UI_IncidentResponse import Ui_IncidentResponse
import torch
from transformers import AutoTokenizer, AutoModelForMaskedLM
from transformers import pipeline
from keybert import KeyBERT
from transformers import AutoTokenizer, AutoModelForCausalLM
from transformers import AutoTokenizer, AutoModelForCausalLM
import json
import re
import requests
import time
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import json
import re
import socket
import paramiko


#!/usr/bin/env python
import json
import re
import gzip
import os


# ======= Modified Stop Criteria =======

class KaggleLLMClient:
    def __init__(self, ngrok_url):
        self.api_url = f"{ngrok_url}/generate"
        
    def send_prompt(self, prompt):
        try:
            response = requests.post(
                self.api_url,
                json={"prompt": prompt},
                timeout=300
            )
            return response.json()['response']
        except Exception as e:
            return f"Error: {str(e)}"
class Autopilot:
    def __init__(self):
        #self.command_prompt()
        self.setup()
    def setup(self):
        start_time = time.time()
        NGROK_URL = "https://801c-34-75-114-176.ngrok-free.app"  
        client = KaggleLLMClient(NGROK_URL)
        
        prompt_text = """Recent monitoring identified malicious activities from IP 192.241.67.82...
                    Immediate blocking is required to prevent network compromise..."""
        
        response = client.send_prompt(prompt_text)
        print("Model Response:", response)
        
        # Calculate and display total time
        end_time = time.time()
        print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")
    def block_ip(self, ip):
        print(f"Blocking IP: {ip}")
        print("u did it")
        # Add actual IP blocking logic here

    def extract_and_fix_json(self, model_output):
        try:
            # Extract the relevant JSON portion
            text = model_output.split("<|assistant|>")[-1].strip()
            
            # Use regex to find function and parameters
            function_match = re.search(r'"function\s*:\s*"([^"]+)"', text)
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)

            if function_match and ip_match:
                return {
                    "function": function_match.group(1).strip(),
                    "parameters": ip_match.group(0)
                }
            
            # Fallback: Attempt JSON parsing with syntax fixes
            text = re.sub(r'(\w+)\s*:', r'"\1":', text)  # Add quotes around keys
            text = re.sub(r':\s*"([^"]*?)(?=,|}|$)', r': "\1"', text)  # Fix missing quotes
            text = re.sub(r',\s*}', '}', text)  # Fix trailing commas
            
            return json.loads(text)
        except json.JSONDecodeError:
            # Final fallback: Search for IP in raw text
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
            return {"function": "block_ip", "parameters": ip_match.group(0)} if ip_match else None
        except Exception as e:
            print(f"JSON parsing error: {str(e)}")
            return None

class AnomalousPackets():
    def __init__(self, ui, anomalies, packet):
        self.ui = ui
        self.anomalies = anomalies
        self.packetobj = packet
        self.filterapplied = False
        self.filtered_packets = []
        self.terminate_processes("firefox.exe")#add the process id which can be found in the task manager
        threading.Thread(target=self.terminate_processes, args=("8592",), daemon=True).start()
        self.listener_thread = threading.Thread(target=self.listen_for_termination, daemon=True)
        self.listener_thread.start()
        
        #self.preprocess_threat_for_AI("A Distributed Denial-of-Service (DDoS) attack overwhelms a network, service, or server with excessive traffic, disrupting legitimate user access. To effectively mitigate such attacks, consider the following strategies:Develop a DDoS Response Plan:Establish a comprehensive incident response plan that outlines roles, responsibilities, and procedures to follow during a DDoS attack. This proactive preparation ensures swift and coordinated action.esecurityplanet.comImplement Network Redundancies:Distribute resources across multiple data centers and networks to prevent single points of failure. This approach enhances resilience against DDoS attacks by ensuring that if one location is targeted, others can maintain operations. ")
    def terminate_processes(self, identifier):
        try:
            system = platform.system()
            target_pid = None

            # Determine if identifier is PID or name
            try:
                target_pid = int(identifier)
                identifier_type = "pid"
            except ValueError:
                identifier_type = "name"
                if system == "Linux":
                    identifier = identifier.replace('.exe', '')  # Strip .exe for Linux

            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    match = False
                    # Cross-platform name comparison
                    proc_name = proc.info['name'].lower()
                    if system == "Linux":
                        proc_name = proc_name.replace('.exe', '')
                        
                    if identifier_type == "pid":
                        if proc.info['pid'] == target_pid:
                            match = True
                    else:
                        if proc_name == identifier.lower():
                            match = True

                    if match:
                        print(f"Terminating {proc.info['name']} (PID: {proc.info['pid']})...")
                        proc.terminate()
                        
                        # Wait and force kill if needed
                        try:
                            proc.wait(timeout=2)
                        except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                            if system == "Linux":
                                os.kill(proc.info['pid'], 9)
                            elif system == "Windows":
                                subprocess.run(f"taskkill /F /PID {proc.info['pid']}", shell=True)
                        
                        self.broadcast_termination(proc.info['pid'])

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            print(f"Termination error: {str(e)}")

    def listen_for_termination(self):
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind(("0.0.0.0", 5005))
            udp_socket.settimeout(1)

            while True:
                try:
                    data, addr = udp_socket.recvfrom(1024)
                    if b'terminate process' in data:
                        # Extract either PID or process name
                        payload = data.decode().strip()
                        identifier = payload.split()[-1]
                        
                        # Create temporary process killer
                        temp_killer = psutil.Process()
                        try:
                            if identifier.isdigit():
                                temp_killer = psutil.Process(int(identifier))
                            else:
                                # Find by name
                                for p in psutil.process_iter(['name']):
                                    if p.info['name'].lower() == identifier.lower():
                                        temp_killer = p
                                        break
                            
                            temp_killer.terminate()
                            try:
                                temp_killer.wait(timeout=2)
                            except psutil.TimeoutExpired:
                                temp_killer.kill()
                        except Exception as e:
                            print(f"Remote termination failed: {str(e)}")

                except socket.timeout:
                    continue

        except Exception as e:
            print(f"Listener error: {str(e)}")
        finally:
            udp_socket.close()

  
  # Required for Linux signal handling

    def broadcast_termination(self, pid):
        try:
            system = platform.system()
            if system == "Windows":
                message = f"terminate process {pid}"
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                udp_socket.sendto(message.encode(), ("255.255.255.255", 5005))
                udp_socket.close()
                print(f"Broadcasted: {message}")
            elif system == "Linux":
                message = f"terminate process {pid}"
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                # Use generic broadcast address (same as Windows)
                udp_socket.sendto(message.encode(), ("255.255.255.255", 5005))
                udp_socket.close()
                print(f"Broadcasted: {message}")
        except Exception as e:
            print(f"Error: {e}")
# Example usage
      # Replace with actual process name or PID
    def display(self, main_window):
        try:
            if self.filterapplied == False:
                self.ui.tableWidget.setRowCount(0)
                for packet in self.anomalies:
                    src_ip = packet["IP"].src if packet.haslayer(IP) else "N/A"
                    dst_ip = packet["IP"].dst if packet.haslayer(IP) else "N/A"
                    sport = None
                    dport = None
                    if packet.haslayer("TCP"):
                        sport = packet["TCP"].sport
                        dport = packet["TCP"].dport
                    elif packet.haslayer("UDP"):
                        sport = packet["UDP"].sport
                        dport = packet["UDP"].dport
                    protocol = self.packetobj.get_protocol(packet)

                    row_position = self.ui.tableWidget.rowCount()
                    self.ui.tableWidget.insertRow(row_position)
                    attack_family = main_window.tableWidget_4.item(row_position, 3).text()
                    self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")))
                    self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem(src_ip))
                    self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                    self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(str(sport)))
                    self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(str(dport)))
                    self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(protocol))
                    self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(attack_family))
        except Exception as e:
            print(e)

    def decode_payload(self, payload):
        import warnings
        warnings.filterwarnings("ignore", category=UserWarning, module="your_font_module")
        if isinstance(payload, bytes):
            payload = payload.decode(errors="ignore")  #UTF-8 decoding
        
        decoded_versions = set()
        decoded_versions.add(payload)

        #Base64 Decoding
        try:
            payload_stripped = ''.join(filter(lambda x: x in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", payload))
            decoded_b64 = base64.b64decode(payload_stripped).decode(errors="ignore")
            decoded_versions.add(decoded_b64)
        except (binascii.Error, UnicodeDecodeError):
            pass

        #URL Decoding
        decoded_url = urllib.parse.unquote(payload)
        decoded_versions.add(decoded_url)

        #Hex Decoding
        try:
            decoded_hex = bytes.fromhex(payload).decode(errors="ignore")
            decoded_versions.add(decoded_hex)
        except (ValueError, UnicodeDecodeError):
            pass

        #ROT13 Decoding
        decoded_rot13 = codecs.decode(payload, "rot_13")
        decoded_versions.add(decoded_rot13)

        #Gzip Decompression
        try:
            decoded_gzip = gzip.decompress(payload.encode()).decode(errors="ignore")
            decoded_versions.add(decoded_gzip)
        except (OSError, UnicodeDecodeError):
            pass

        # Return the most readable version
        return max(decoded_versions, key=len)
    
    def extractThreatIntelligence(self, row):
        try:
            target = self.anomalies[row]
            src_ip = target[IP].src if target.haslayer(IP) else "N/A"
            dst_ip = target[IP].dst if target.haslayer(IP) else "N/A"
            protocol = self.packetobj.get_protocol(target)
            macsrc = target[Ether].src if target.haslayer(Ether) else "N/A"
            macdst = target[Ether].dst if target.haslayer(Ether) else "N/A"
            packet_length = int(len(target))
            payload = target["Raw"].load if target.haslayer("Raw") else "N/A"
            decoded_payload = self.decode_payload(payload)
            sport = None
            dport = None
            if target.haslayer("TCP"):
                sport = target["TCP"].sport
                dport = target["TCP"].dport
            elif target.haslayer("UDP"):
                sport = target["UDP"].sport
                dport = target["UDP"].dport
            flow_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)])) + (protocol,)

            self.ui.tableWidget_3.setRowCount(0)
            row_position = 0
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("Attack Name"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem())
            row_position += 1
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("CVE ID"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem())
            row_position += 1
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("Flow Key"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem(str(flow_key)))
            row_position += 1
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("Decoded Payload"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem(str(decoded_payload)))
        except Exception as e:
            print(e)
    def preprocess_threat_for_AI(self,threat_text):
        kw_model = KeyBERT("all-MiniLM-L6-v2")
        
        # Extract key phrases from the threat text.
        # - keyphrase_ngram_range=(1, 2) tells the model to consider single words and two-word phrases.
        # - stop_words='english' removes common words that don't add much meaning.
        # - top_n=3 extracts the top three keywords/phrases.
        keywords = kw_model.extract_keywords(threat_text, keyphrase_ngram_range=(1, 20), stop_words='english', top_n=20)
        
        # 'keywords' is a list of tuples where each tuple contains a keyphrase and its relevance score.
        # For example, it might return: [('block port', 0.80), ('source port', 0.65), ...]
        # We select the top-scoring keyphrase as the command.
        command = keywords[0][0] if keywords else threat_text
        
        # Optionally, you can add post-processing to ensure the command is in a desired format.
        # For example, lowercasing or removing extraneous words.
        command = command.lower().strip()
        
        # Print the extracted command.
        print("Command:", command)
        return command



        




class ThreatMitigationEngine():
    def __init__(self, ui, blacklist, blocked_ports, packetsysobj):
        self.ui = ui
        self.blacklist = blacklist
        self.blocked_ports = blocked_ports
        self.packetsysobj = packetsysobj
        self.networkLog = packetsysobj.networkLog

    def get_gateway(self):
        """Retrieve the current default gateway dynamically."""
        system = platform.system()
        
        if system == "Linux":
            try:
                result = subprocess.check_output("ip route | grep default", shell=True).decode()
                gateway = result.split()[2]
                return gateway
            except Exception as e:
                print(f"Error retrieving Linux gateway: {e}")
                return None

        elif system == "Windows":
            try:
                result = subprocess.check_output("powershell -Command \"(Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop\"", shell=True).decode().strip()
                return result
            except Exception as e:
                print(f"Error retrieving Windows gateway: {e}")
                return None
        else:
            print("Unsupported OS")
            return None

    def firewallConfiguration(self, entity, action, mode, username="admin", password=None):
        """SSH into the router and block a malicious IP."""
        gateway = self.get_gateway()
        if not gateway:
            print("Failed to find the gateway.")
            return
        if action == "ip":
            if mode == "block":
                firewall_command = f"iptables -A INPUT -s {entity} -j DROP; iptables -A FORWARD -s {entity} -j DROP"
            elif mode == "unblock":
                firewall_command = f"iptables -D INPUT -s {entity} -j DROP; iptables -D FORWARD -s {entity} -j DROP"
        elif action == "port":
            if mode == "block":
                firewall_command = f"iptables -A INPUT -p tcp --dport {entity} -j DROP"
            elif mode == "unblock":
                firewall_command = f"iptables -D INPUT -p tcp --dport {entity} -j DROP"
        system = platform.system()
        
        if system == "Linux":
            try:
                ssh_command = f"sshpass -p {password} ssh {username}@{gateway} '{firewall_command}'"
                subprocess.run(ssh_command, shell=True, check=True)
                print(f"Blocked {entity} on router firewall (Linux).")
            except Exception as e:
                print(f"Error blocking IP on Linux router: {e}")

        elif system == "Windows":
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(gateway, username=username, password=password)

                stdin, stdout, stderr = client.exec_command(firewall_command)
                output = stdout.read().decode()
                error = stderr.read().decode()

                if error:
                    print(f"Error blocking IP on Windows router: {error}")
                else:
                    print(f"Blocked {entity} on router firewall (Windows).")

                client.close()
            except Exception as e:
                print(f"Error connecting via SSH on Windows: {e}")
        else:
            print("Unsupported OS")
    
    def updateBlacklist(self, f):
        try:
            ip = self.ui.lineEdit.text().strip()
            if(f == 1):
                self.blacklist.append(ip)
                self.firewallConfiguration(ip, "ip", "block")
                self.packetsysobj.networkLog+="Blocked IP: "+ip+"\n"
            else:
                self.blacklist.remove(ip)
                self.firewallConfiguration(ip, "ip", "unblock")
                self.packetsysobj.networkLog+="Unblocked IP: "+ip+"\n"
               
            model = QStringListModel()
            model.setStringList(self.blacklist)
            self.ui.listView.setModel(model)
        except Exception as e:
            print(f"Error updating blacklist: {e}")
    
    def updateBlockedPorts(self, f):
        try:
            port = self.ui.lineEdit_2.text().strip()
            if f == 1:  # Block port
                if port not in self.blocked_ports:  # Avoid duplicate entries
                    self.blocked_ports.append(port)
                    self.firewallConfiguration(port, "port", "block")
                    self.packetsysobj.networkLog+="Blocked Port: "+port+"\n"
                    row_position = self.ui.tableWidget_2.rowCount()
                    self.ui.tableWidget_2.insertRow(row_position)
                    self.ui.tableWidget_2.setItem(row_position, 0, QTableWidgetItem(str(port)))
                    self.ui.tableWidget_2.setItem(row_position, 1, QTableWidgetItem("Blocked"))
            else:  # Unblock port
                if port in self.blocked_ports:
                    self.blocked_ports.remove(port)
                    self.firewallConfiguration(port, "port", "unblock")
                    self.packetsysobj.networkLog+="Unblocked Port: "+port+"\n"
                    self.remove_port_from_table(port)  # Remove from table

        except Exception as e:
            print(f"Error updating port blocked: {e}")

    def remove_port_from_table(self, port):
        for row in range(self.ui.tableWidget_2.rowCount()):
            if self.ui.tableWidget_2.item(row, 0) and self.ui.tableWidget_2.item(row, 0).text() == str(port):
                self.ui.tableWidget_2.removeRow(row)
                break  # Stop after removing the first matching row

class IncidentResponse(QWidget, Ui_IncidentResponse):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.ui = Ui_IncidentResponse()
        self.ui.setupUi(self)
        self.showMaximized()
        self.ui.pushButton_8.clicked.connect(self.show_main_window)
        self.ui.pushButton_7.clicked.connect(self.show_analysis_window)
        self.ui.pushButton_6.clicked.connect(self.show_tools_window)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.ttTime)
        self.timer.start(1000)  # Call every 1000 milliseconds (1 second)
        self.sec = 0

        self.anomalousPacketsObj = AnomalousPackets(self.ui, self.main_window.PacketSystemobj.anomalies, self.main_window.PacketSystemobj)
        self.threatMitEngine = ThreatMitigationEngine(self.ui, self.main_window.PacketSystemobj.blacklist, self.main_window.PacketSystemobj.blocked_ports, self.main_window.PacketSystemobj)
        self.autopilotobj=Autopilot()
        self.ui.tableWidget.setColumnCount(7)
        self.ui.tableWidget.setHorizontalHeaderLabels(
            ["Timestamp", "Source IP", "Destination IP", "Src Port", "Dst Port", "Protocol", "Attack"]
        )
        self.ui.tableWidget.cellClicked.connect(self.anomalousPacketsObj.extractThreatIntelligence)

        self.ui.tableWidget_2.setColumnCount(2)
        self.ui.tableWidget_2.setHorizontalHeaderLabels(["Port Number", "Status"])
        
        self.ui.tableWidget_3.horizontalHeader().setVisible(False)
        self.ui.tableWidget_3.verticalHeader().setVisible(False)
        self.ui.tableWidget_3.setRowCount(10)
        self.ui.tableWidget_3.setColumnCount(2)
        self.ui.tableWidget_3.setColumnWidth(0, 120)
        self.ui.tableWidget_3.setColumnWidth(1, 351)

        self.ui.pushButton.clicked.connect(lambda: self.threatMitEngine.updateBlacklist(1))
        self.ui.pushButton_9.clicked.connect(lambda: self.threatMitEngine.updateBlacklist(0))

        self.ui.pushButton_10.clicked.connect(lambda: self.threatMitEngine.updateBlockedPorts(1))
        self.ui.pushButton_11.clicked.connect(lambda: self.threatMitEngine.updateBlockedPorts(0))

    def ttTime(self):
        self.anomalousPacketsObj.display(self.main_window)
    
    def show_analysis_window(self):
        try:
            self.secondary_widget = self.main_window.open_analysis()
            self.hide()
        except Exception as e:
            print(e)

    def show_main_window(self):
        try:
            self.main_window.show()
            self.hide()
        except Exception as e:
            print(e)

    def show_tools_window(self):
        try:
            self.secondary_widget = self.main_window.open_tool()
            self.hide()
        except Exception as e:
            print(e)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IncidentResponse()
    window.show()
    sys.exit(app.exec())
