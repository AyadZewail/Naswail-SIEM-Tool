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
from scapy.layers.inet import IP, TCP, UDP,ICMP
from scapy.layers.dns import DNS
from UI_IncidentResponse import Ui_IncidentResponse

class AnomalousPackets():
    def __init__(self, ui, anomalies, packet):
        self.ui = ui
        self.anomalies = anomalies
        self.packetobj = packet
        self.filterapplied = False
        self.filtered_packets = []

    def display(self):
        try:
            if self.filterapplied == False:
                self.ui.tableWidget.setRowCount(0)
                for packet in self.anomalies:
                    src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                    dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                    protocol = self.packetobj.get_protocol(packet)
                    macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                    macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                    # Extract packet length
                    packet_length = int(len(packet))
                    payload = packet["Raw"].load if packet.haslayer("Raw") else "N/A"          
                    # Extract port information for TCP/UDP
                    sport = None
                    dport = None
                    if packet.haslayer("TCP"):
                            sport = packet["TCP"].sport
                            dport = packet["TCP"].dport
                    elif packet.haslayer("UDP"):
                            sport = packet["UDP"].sport
                            dport = packet["UDP"].dport

                    row_position = self.ui.tableWidget.rowCount()
                    self.ui.tableWidget.insertRow(row_position)
                    self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")))
                    self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem(src_ip))
                    self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                    self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(macsrc))
                    self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(macdst))
                    self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(str(sport)))
                    self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(str(dport)))
                    self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem(protocol))
                    self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(packet_length)))
                    self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(payload)))
        except Exception as e:
            print(e)


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

        self.ui.tableWidget.setColumnCount(10)
        self.ui.tableWidget.setHorizontalHeaderLabels(
            ["Timestamp", "Source IP", "Destination IP", "MAC Src", "MAC Dst", "Src Port", "Dst Port", "Protocol", "Length", "Payload"]
        )

        self.ui.tableWidget_2.setColumnCount(2)
        self.ui.tableWidget_2.setHorizontalHeaderLabels(["Port Number", "Status"])

        self.ui.pushButton.clicked.connect(lambda: self.blacklistObj.updateBlacklist(1))
        self.ui.pushButton_9.clicked.connect(lambda: self.blacklistObj.updateBlacklist(0))

        self.ui.pushButton_10.clicked.connect(lambda: self.portBlockingObj.updateBlockedPorts(1))
        self.ui.pushButton_11.clicked.connect(lambda: self.portBlockingObj.updateBlockedPorts(0))

    def ttTime(self):
        self.anomalousPacketsObj.display()
    
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
