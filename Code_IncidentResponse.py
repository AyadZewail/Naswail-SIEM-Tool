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
class AnomalousPackets():
    def __init__(self, ui, anomalies, packet):
        self.ui = ui
        self.anomalies = anomalies
        self.packetobj = packet
        self.filterapplied = False
        self.filtered_packets = []
        
        self.preprocess_threat_for_AI("A Distributed Denial-of-Service (DDoS) attack overwhelms a network, service, or server with excessive traffic, disrupting legitimate user access. To effectively mitigate such attacks, consider the following strategies:Develop a DDoS Response Plan:Establish a comprehensive incident response plan that outlines roles, responsibilities, and procedures to follow during a DDoS attack. This proactive preparation ensures swift and coordinated action.esecurityplanet.comImplement Network Redundancies:Distribute resources across multiple data centers and networks to prevent single points of failure. This approach enhances resilience against DDoS attacks by ensuring that if one location is targeted, others can maintain operations. ")

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



        




class Blacklist():
    def __init__(self, ui, blacklist,packetsysobj):
        self.ui = ui
        self.blacklist = blacklist
        self.packetsysobj = packetsysobj
        self.log=packetsysobj.networkLog

    def updateBlacklist(self, f):
        try:
            ip = self.ui.lineEdit.text().strip()
            if(f == 1):
                self.blacklist.append(ip)
                self.block_ip(ip)
                self.packetsysobj.networkLog+="Blocked IP: "+ip+"\n"
            else:
                self.blacklist.remove(ip)
                self.unblock_ip(ip)
                self.packetsysobj.networkLog+="Unblocked IP: "+ip+"\n"
               
            model = QStringListModel()
            model.setStringList(self.blacklist)
            self.ui.listView.setModel(model)
        except Exception as e:
            print(f"Error updating blacklist: {e}")

    def block_ip(self,ip):
        system = platform.system()
        
        if system == "Windows":
            print(f"Blocking {ip} on Windows Firewall")
            os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
            os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}')
        
        elif system == "Linux":
            print(f"Blocking {ip} using iptables")
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
        
        else:
            print("Unsupported OS")
    def unblock_ip(self,ip):
        system = platform.system()
        
        if system == "Windows":
            print(f"Unblocking {ip} from Windows Firewall")
            os.system(f'netsh advfirewall firewall delete rule name="Block {ip}"')

        elif system == "Linux":
            print(f"Unblocking {ip} from iptables")
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        
        else:
            print("Unsupported OS")

class PortBlocking():
    def __init__(self, ui, blocked_ports,packetsysobj):
        self.ui = ui
        self.blocked_ports = blocked_ports
        self.packetsysobj = packetsysobj
        self.log=packetsysobj.networkLog
    def updateBlockedPorts(self, f):
        try:
            port = self.ui.lineEdit_2.text().strip()
            if f == 1:  # Block port
                if port not in self.blocked_ports:  # Avoid duplicate entries
                    self.blocked_ports.append(port)
                    self.block_port(port)
                    self.packetsysobj.networkLog+="Blocked Port: "+port+"\n"
                    row_position = self.ui.tableWidget_2.rowCount()
                    self.ui.tableWidget_2.insertRow(row_position)
                    self.ui.tableWidget_2.setItem(row_position, 0, QTableWidgetItem(str(port)))
                    self.ui.tableWidget_2.setItem(row_position, 1, QTableWidgetItem("Blocked"))
            else:  # Unblock port
                if port in self.blocked_ports:
                    self.blocked_ports.remove(port)
                    self.unblock_port(port)
                    self.packetsysobj.networkLog+="Unblocked Port: "+port+"\n"
                    self.remove_port_from_table(port)  # Remove from table

        except Exception as e:
            print(f"Error updating port blocked: {e}")

    def remove_port_from_table(self, port):
        
        for row in range(self.ui.tableWidget_2.rowCount()):
            if self.ui.tableWidget_2.item(row, 0) and self.ui.tableWidget_2.item(row, 0).text() == str(port):
                self.ui.tableWidget_2.removeRow(row)
                break  # Stop after removing the first matching row

    def block_port(self,port):
        os_name = platform.system()

        if os_name == "Windows":
            os.system(f'netsh advfirewall firewall add rule name="BlockPort{port}" dir=in action=block protocol=TCP localport={port}')
            print(f"Blocked port {port} on Windows.")
        elif os_name == "Linux":
            os.system(f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP")
            print(f"Blocked port {port} on Linux.")
        else:
            print("Unsupported OS.")

    def unblock_port(self,port):
        os_name = platform.system()

        if os_name == "Windows":
            os.system(f'netsh advfirewall firewall delete rule name="BlockPort{port}" protocol=TCP localport={port}')
            print(f"Unblocked port {port} on Windows.")
            
        elif os_name == "Linux":
            os.system(f"sudo iptables -D INPUT -p tcp --dport {port} -j DROP")
            print(f"Unblocked port {port} on Linux.")
        else:
            print("Unsupported OS.")

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
        self.blacklistObj = Blacklist(self.ui, self.main_window.PacketSystemobj.blacklist,self.main_window.PacketSystemobj)
        self.portBlockingObj = PortBlocking(self.ui, self.main_window.PacketSystemobj.blocked_ports,self.main_window.PacketSystemobj)

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

        self.ui.pushButton.clicked.connect(lambda: self.blacklistObj.updateBlacklist(1))
        self.ui.pushButton_9.clicked.connect(lambda: self.blacklistObj.updateBlacklist(0))

        self.ui.pushButton_10.clicked.connect(lambda: self.portBlockingObj.updateBlockedPorts(1))
        self.ui.pushButton_11.clicked.connect(lambda: self.portBlockingObj.updateBlockedPorts(0))

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
