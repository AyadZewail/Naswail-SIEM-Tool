import sys
import numpy as np
import pandas as pd
import time
import psutil
import os
import platform
import subprocess
import ipaddress
import matplotlib.pyplot as plt
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest  
from scapy.layers.inet import IP, TCP, UDP,ICMP
from scapy.layers.dns import DNS
from statistics import mean, mode, stdev
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from math import pi
from datetime import datetime
from UI_Main import Ui_MainWindow
from Code_Analysis import Window_Analysis
from Code_Tools import Window_Tools
from Code_IncidentResponse import IncidentResponse
from PyQt6 import QtCore, QtWidgets
from collections import defaultdict
import re
import traceback
import threading
import ctypes
#sudo /home/hamada/Downloads/Naswail-SIEM-Tool-main/.venv/bin/python /home/hamada/Downloads/Naswail-SIEM-Tool-main/Code_Main.py

packetInput = 0
packetFile = None
clearRead = 0 
packetIndex = 0

class SplashScreen(QSplashScreen):
    def __init__(self):
        # Get the screen dimensions
        screen = QApplication.primaryScreen().size()
        screen_width = screen.width()
        screen_height = screen.height()
        
        logo_path = "logo.png"
        pixmap = QPixmap(logo_path)
        
        # If logo.png doesn't exist, try the alternative name
        if pixmap.isNull():
            logo_path = "naswail_logo.png"
            pixmap = QPixmap(logo_path)
        
        # Create a larger canvas for full screen
        if not pixmap.isNull():
            # Scale logo to appropriate size (not too large, not too small)
            logo_height = int(screen_height * 0.4)  # 40% of screen height
            scaled_pixmap = pixmap.scaled(logo_height, logo_height, 
                                          Qt.AspectRatioMode.KeepAspectRatio, 
                                          Qt.TransformationMode.SmoothTransformation)
            
            # Create a new full-size pixmap with background color
            full_pixmap = QPixmap(screen_width, screen_height)
            full_pixmap.fill(QColor("#17292B"))  # Dark background color
            
            # Create a painter to draw on the full pixmap
            painter = QPainter(full_pixmap)
            
            # Draw the logo in the center
            logo_x = (screen_width - scaled_pixmap.width()) // 2
            logo_y = (screen_height - scaled_pixmap.height()) // 2 - 50  # Slight offset for progress bar
            painter.drawPixmap(logo_x, logo_y, scaled_pixmap)
            painter.end()
            
            pixmap = full_pixmap
        
        super().__init__(pixmap)
        
        # Set window as frameless and fullscreen
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        
        # Progress bar setup
        progress_width = int(screen_width * 0.6)  # 60% of screen width
        progress_height = 40
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(
            (screen_width - progress_width) // 2,  # center horizontally 
            logo_y + scaled_pixmap.height() + 50,  # position below the logo
            progress_width, 
            progress_height
        )
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #5A595C;
                border-radius: 5px;
                background-color: #2D2A2E;
                text-align: center;
                color: white;
                font-size: 14pt;
            }
            
            QProgressBar::chunk {
                background-color: #9CB7C8;
                width: 10px;
                margin: 0.5px;
            }
        """)
        
        # Add label for text
        self.label = QLabel("Loading...", self)
        self.label.setStyleSheet("color: white; font-size: 18pt; font-weight: bold; background: transparent;")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setGeometry(0, self.progress_bar.y() - 60, screen_width, 50)
        
        # Timer for progress updates
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.progress_value = 0
        
        # Loading messages
        self.loading_messages = [
            "Starting Naswail SIEM...",
            "Loading network modules...",
            "Initializing packet capture...",
            "Setting up analysis engine...",
            "Loading security components...",
            "Preparing interface...",
            "Almost ready..."
        ]
        self.message_index = 0
    
    def start_progress(self):
        self.timer.start(30)
        
    def update_progress(self):
        self.progress_value += 1
        self.progress_bar.setValue(self.progress_value)
        
        # Update loading message periodically
        if self.progress_value % 14 == 0 and self.message_index < len(self.loading_messages):
            self.label.setText(self.loading_messages[self.message_index])
            self.message_index += 1
            
        # When progress reaches 100, stop the timer
        if self.progress_value >= 100:
            self.timer.stop()
    
    # Override mousePressEvent to prevent clicking through splash screen
    def mousePressEvent(self, event):
        pass

class ApplicationsSystem:
    def __init__(self, ui_main_window):
        self.ui = ui_main_window
        self.apps = dict()
        self.packet_obj = None  
    def set_packet_system(self, packet_obj):
        #the purpose of this function is to set the packet system object later on due to circular import
        self.packet_obj = packet_obj
    def get_applications_with_ports(self):
        try:
            apps_with_ports = []

            for proc in psutil.process_iter(attrs=['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
                try:
                    pid = proc.info['pid']
                    app_name = proc.info['name']
                    app_status = proc.info['status']
                    app_cpu = proc.info['cpu_percent']
                    app_mem = proc.memory_percent()
                    connections = psutil.Process(pid).net_connections(kind='inet')
                    connection_details = []

                    for conn in connections:
                        if conn.laddr:  # Check if there is a valid local address
                            local_ip, local_port = conn.laddr
                            connection_details.append({
                                "IP": local_ip,
                                "Port": local_port
                            })

                    entry = {
                        "Application": app_name,
                        "IP": local_ip,
                        "Port": local_port,
                        "Status": app_status,
                        "CPU": app_cpu,
                        "Memory": app_mem,
                    }

                    if not any(existing_entry["Application"] == entry["Application"] and existing_entry["IP"] == "0.0.0.0" for existing_entry in apps_with_ports):
                        apps_with_ports.append(entry)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

            self.apps = apps_with_ports
            self.ui.tableWidget_3.setRowCount(0)
            for app in self.apps:
                row_position = self.ui.tableWidget_3.rowCount()
                self.ui.tableWidget_3.insertRow(row_position)
                self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem(str(app["Port"])))
                self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem(str(app["Application"])))
                self.ui.tableWidget_3.setItem(row_position, 2, QTableWidgetItem(str(app["IP"])))
                self.ui.tableWidget_3.setItem(row_position, 3, QTableWidgetItem(str(app["CPU"])))
                self.ui.tableWidget_3.setItem(row_position, 4, QTableWidgetItem(str(app["Memory"])))
        except Exception as e:
            print(f"Error in get_applications_with_ports function: {e}")
    def analyze_app(self, row):
        try:
            #this function filters by the clicked application
            self.packet_obj.application_filter_flag = True
            target_app = self.apps[row]
            self.ui.tableWidget.setRowCount(0) 

            self.filtered_packets = []
            for packet in self.packet_obj.packets:
                macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                # Extract packet length
                packet_length = int(len(packet))

            # Extract IP version
                ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                # Extract port information for TCP/UDP
                sport = None
                dport = None
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport

                packet_length = int(len(packet))
                src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                protocol = self.packet_obj.get_protocol(packet)
                port = packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
                layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                if target_app["IP"] in src_ip.lower() or target_app["IP"] in dst_ip.lower() or str(target_app["Port"]) in str(port):
                    self.packet_obj.filtered_packets.append(packet)

                    row_position = self.ui.tableWidget.rowCount()
                    self.ui.tableWidget.insertRow(row_position)
                    self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(packet.time).strftime("%I:%M:%S %p")))
                    self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem(src_ip))
                    self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                    self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(protocol))
                    self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(layer))
                    # Add MAC addresses and port info to the table
                    self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(macsrc))
                    self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(macdst))
                    self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem(str(sport) if sport else "N/A"))
                    self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(dport) if dport else "N/A"))
                    self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(packet_length)))
                    self.ui.tableWidget.setItem(row_position, 10, QTableWidgetItem(ip_version))
        except:
            print("Error in analyze_app function")
class SensorSystem:
    def __init__(self, ui_main_window):
        self.ui = ui_main_window
        self.sen_info = []#list of tuble containing the name of the sensor and its mac
        self.sensor_packet = []
        self.sensors_name = []
        self.senFlag = -1#indicate filtering by sensors
        self.singleSenFlag = -1#indicate filtering by single sensor
        self.sen_ct = 0
        self.packet_obj = None  # Delay initialization
        self.ct_sensor_packet=[]#used in analyis to know the number packets in realtion to each sensor    
        self.sensors = {}
        

    def set_packet_system(self, packet_obj):       
        self.packet_obj = packet_obj

    def filter_sensors(self, row, col):
        try:#filters by sensor
            self.singleSenFlag *= -1
            self.senFlag = -1
         
            if(self.singleSenFlag == 1):
                sensor_mac = self.ui.tableWidget_2.item(row, col).text()
                self.ui.tableWidget.setRowCount(0)
                for packet in self.packet_obj.packets:

                    src_mac = packet["Ether"].src if packet.haslayer("Ether") else "N/A"
                    dst_mac = packet["Ether"].dst if packet.haslayer("Ether") else "N/A"
                    protocol = self.packet_obj.get_protocol(packet)
                    port = packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
                    ip_src=packet["IP"].src if packet.haslayer("IP") else "N/A"
                    ip_dst=packet["IP"].dst if packet.haslayer("IP") else "N/A"
                    packet_length = int(len(packet))
                    sport=packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
                    dport=packet["TCP"].dport if packet.haslayer("TCP") else "N/A"
                    ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                    layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)

                    if sensor_mac.lower() in src_mac.lower() or sensor_mac.lower() in dst_mac.lower():
                        self.sensor_packet.append(packet)
                        row_position = self.ui.tableWidget.rowCount()
                        self.ui.tableWidget.insertRow(row_position)
                        self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(packet.time).strftime("%I:%M:%S %p")))
                        self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem(ip_src))
                        self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem(ip_dst))
                        self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(protocol))
                        self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(layer))
                        self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(src_mac))
                        self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(dst_mac))
                        
                        
                        self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem(str(sport) if sport else "N/A"))
                        self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(dport) if dport else "N/A"))
                        self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(packet_length)))
                        self.ui.tableWidget.setItem(row_position, 10, QTableWidgetItem(ip_version))
        except Exception as e:
            print(f"error in filter sensor function:{e}")

    #end of filter
    def updateSensor(self, a):
        try:
            #updates the name of the sensor
            senName = self.ui.lineEdit_3.text().strip()
            senMAC = self.ui.lineEdit_4.text().strip()
        
            if(a == 1):
                self.sen_info.append(senName)
                self.sen_info.append(0)
                self.sensors[senName] = senMAC
                
            

            else:
                self.sensors.pop(senName)
            
            self.sensors_name.append(senName)
        
            #print(self.sensors)
            plt.close()
            self.show_donut_chart()
            self.displaySensorTable()
        except:
            print("error in update sensor function")
    def displaySensorTable(self):
        try:
            
            self.show_donut_chart
            self.ui.tableWidget_2.setRowCount(0)
            for name, mac in self.sensors.items():
                row_position = self.ui.tableWidget_2.rowCount()
                self.ui.tableWidget_2.insertRow(row_position)
                self.ui.tableWidget_2.setItem(row_position, 0, QTableWidgetItem(str(name)))
                self.ui.tableWidget_2.setItem(row_position, 1, QTableWidgetItem(str(mac)))
        except:
            print("error in display sensor table function")
        
    def show_donut_chart(self):
        try:
            if  self.packet_obj.typeOFchartToPlot==0:
                self.ui.graphicsView_2.setScene(None)
                return
            sizes = [1]  
            labels = ['']  
            s=0
            for s in range(len(self.sensors)):
                sizes.append(s)
                labels.append('')
            
            colors = [
                '#E0F7F5', '#B3ECE6', '#8FE0D8',  # Light turquoise variants
                '#40E0D0', '#36C9B0', '#2DB39E',  # Base + hover/pressed states
                '#249C8A', '#1B8676', '#126F62',  # Darker turquoise
                '#0A594E', '#03433A', '#002D26',  # Deep teal variants
                '#001612', '#008080', '#00CED1'    # Darkest tones + accent variations
            ]
            fig, ax = plt.subplots(figsize=(6, 6))  
            
            # Draw the donut chart
            wedges, texts = ax.pie(
                sizes,
                labels=labels,
                startangle=90,
                colors=colors,
                wedgeprops=dict(width=0.3)  # Create the "donut" effect
            )
            
            # Set aspect ratio to be equal
            ax.axis('equal')
            ax.set_title('Sensors')
            
            # Ensure transparency
            fig.patch.set_visible(False)  # Completely hide the figure background
            ax.patch.set_alpha(0)         # Transparent axes background
            
            # Render the figure to a Qt widget
            canvas = FigureCanvas(fig)
            canvas.setStyleSheet("background: transparent;")  # Ensure no background for the canvas
            canvas.setGeometry(0, 0, self.ui.graphicsView_2.width(), self.ui.graphicsView_2.height())
            
            # Set up a transparent scene for QGraphicsView
            scene = QGraphicsScene()
            scene.setBackgroundBrush(Qt.GlobalColor.transparent)  # Ensure the scene background is transparent
            scene.addWidget(canvas)
            self.ui.graphicsView_2.setScene(scene)
            plt.close(fig)
        except Exception as e:
            print(f"error in show donut chart function:{e}")
    def toggleSenFlag(self):
        try:#this function filters by all sesnors
            self.senFlag *= -1
            self.singleSenFlag = -1
        
            if self.senFlag == 1:
                self.ui.tableWidget.setRowCount(0)
                
                for packet in self.packet_obj.packets:
                    src_mac = packet["Ether"].src if packet.haslayer("Ether") else "N/A"
                    dst_mac = packet["Ether"].dst if packet.haslayer("Ether") else "N/A"
                    protocol = self.packet_obj.get_protocol(packet)
                    port = packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
                    ip_src=packet["IP"].src if packet.haslayer("IP") else "N/A"
                    ip_dst=packet["IP"].dst if packet.haslayer("IP") else "N/A"
                    packet_length = int(len(packet))

                # Extract IP version
                    ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                    # Extract port information for TCP/UDP
                    sport = None
                    dport = None
                    timestamp = float(packet.time)
                    readable_time = datetime.fromtimestamp(timestamp).strftime("%I:%M:%S %p")
                    time="N/A"
                    if packet.haslayer("TCP"):
                        sport = packet["TCP"].sport
                        dport = packet["TCP"].dport
                    elif packet.haslayer("UDP"):
                        sport = packet["UDP"].sport
                        dport = packet["UDP"].dport

                    

                    for sensor_name, sensor_mac in self.sensors.items():
                        if sensor_mac.lower() in src_mac.lower() or sensor_mac.lower() in dst_mac.lower():
                            self.sensor_packet.append(packet)
                            for s in range(0,len(self.sen_info)-1,2):
                                if self.sen_info[s]==sensor_name:
                                    self.sen_info[s+1]+=1
                                
                                
                            row_position = self.ui.tableWidget.rowCount()
                            self.ui.tableWidget.insertRow(row_position)  

                            #self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(packet.time).strftime("%I:%M:%S %p")))
                            self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(readable_time))
                            self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem(ip_src))
                            self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem(ip_dst))
                            self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(protocol))
                            self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(src_mac))
                            self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(dst_mac))
                            self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(str(port)))
                            self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem(str(ip_version)))
                            self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(packet_length)))
                            self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(sport)))
                            self.ui.tableWidget.setItem(row_position, 10, QTableWidgetItem(str(dport)))
                self.ct_sensor_packet.append(self.sen_ct)
        except Exception as e:
            print(f"nuh uh no sensor filtering for some reason intoggle senseflag function:{e}") 
class NetworkActivity:#helper class
        def __init__(self):
            self.mac_of_device = ''
            self.actvity = ''  
class PacketSystem:
    def __init__(self, ui_main_window):
        self.ui = ui_main_window
        self.packets = []
        self.process_packet_index=0
        self.bandwidth_data = []
        self.captured_packets = []
        self.qued_packets = []
        self.pcap_packets = []
        self.pcap_process_packet_index = 0
        self.corrupted_packet = []
        self.filtered_packets = []
        self.packet_features = []
        self.new_packet_features = []
        self.total_inside_packets = 0
        self.total_outside_packets = 0
        self.inside_packets = 0
        self.outside_packets = 0
        self.inside_percentage = 0
        self.networkLog=""
        self.filterapplied = False
        self.application_filter_flag=False
        self.packet_stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0,"http":0,"https":0,"dns":0,"dhcp":0,"ftp":0,"telnet":0}
        self.anomalies = []
        self.sensor_obj = None
        self.capture = -1
        self.blacklist = []
        self.blocked_ports = []
        self.tot_tcp_packets = 0
        self. tot_udp_packets = 0
        self.tot_icmp_packets = 0
        self.rate_of_packets=0
        self.recently_qued_packets=0
        self.typeOFchartToPlot=0
        self.packetfile = 1
        self.local_packets = []
        self.snort_alerts = defaultdict(list)
        system = platform.system()
        system = platform.system().lower()
        if system == "windows":
            self.snort_rules = self.load_snort_rule_names("C:\\Snort\\rules\\custom.rules")
            self.log_thread = threading.Thread(target=self.monitor_snort_logs, args=("C:\\Snort\\log\\alert.ids",), daemon=True)
        elif system == "linux":
            self.snort_rules = self.load_snort_rule_names("/etc/snort/rules/custom.rules")
            self.log_thread = threading.Thread(target=self.monitor_snort_logs, args=("/var/log/snort/alert",), daemon=True)
            self.log_thread = threading.Thread(target=self.monitor_snort_logs, args=("/var/log/snort/alert",), daemon=True)
        self.log_thread.start()
        self.list_of_activity=[]

    def set_sensor_system(self, sensor_obj):
        self.sensor_obj = sensor_obj

    def load_snort_rule_names(self, rule_file):
        """Loads Snort rule SIDs and their corresponding attack labels."""
        sid_to_attack = {}

        with open(rule_file, 'r') as f:
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

    def monitor_snort_logs(self, log_file):
        """Tails Snort's alert_fast log file and extracts attack labels."""
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

                            if (src_ip, dst_ip) not in self.snort_alerts:
                                self.snort_alerts[(src_ip, dst_ip)].append(attack_label)
                                print(f"Detected: {attack_label} from {src_ip}, {sport} to {dst_ip}, {dport}")
                                for packet in self.qued_packets:
                                    msrc_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                                    mdst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                                    if msrc_ip == src_ip and mdst_ip == dst_ip:
                                            self.anomalies.append(packet)
                                            current_time = datetime.now().strftime("%H:%M:%S")
                                            self.networkLog+=current_time+"/  "+"An anomaly occured"+"\n"
                                            row_position = self.ui.tableWidget_4.rowCount()
                                            self.ui.tableWidget_4.insertRow(row_position)
                                            self.ui.tableWidget_4.setItem(row_position, 0, QTableWidgetItem(current_time))
                                            self.ui.tableWidget_4.setItem(row_position, 1, QTableWidgetItem(src_ip))
                                            self.ui.tableWidget_4.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                                            self.ui.tableWidget_4.setItem(row_position, 3, QTableWidgetItem(str(self.snort_alerts[(src_ip, dst_ip)][0])))
                                                    

                except Exception as e:
                    print(f"Error processing log line: {e}")
                    tb = traceback.format_exc()
                    print("Traceback details:")
                    print(tb)
                    continue
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
    def draw_gauge(self):
        try:

            if self.sensor_obj.senFlag == 1 or self.sensor_obj.singleSenFlag == 1:
                self.typeOFchartToPlot=1
                
            if self.typeOFchartToPlot == 1:
                self.ui.graphicsView_2.setScene(None)
                self.sensor_obj.show_donut_chart()
                return
            #clear first
            view_width = self.ui.graphicsView_2.width()
            view_height = self.ui.graphicsView_2.height()

            # dpi is the size
            dpi = 100
            fig_width = view_width / dpi
            fig_height = view_height / dpi

            
            fig = Figure(figsize=(fig_width, fig_height), dpi=dpi)
            ax = fig.add_subplot(111, polar=True)
            fig.patch.set_alpha(0)  
            ax.set_facecolor("none")
            start_angle = -np.pi / 2  # start angle (the left side of the gauge)
            end_angle = np.pi / 2     # End angle the right side 180 degree
            min_value = 0
            max_value = 1000
            current_value = max(min(self.rate_of_packets, max_value), min_value)  # Clamp value between 0 and 1000
            # Compute the needle angle
            angle = start_angle + (current_value / max_value) * (end_angle - start_angle)
            sections = [
    (0, 0.1667, '#40E0D0'),     # Turquoise (main accent)
    (0.1667, 0.3333, '#36C9B0'), # Hover turquoise
    (0.3333, 0.5, '#2DB39E'),    # Pressed turquoise
    (0.5, 0.6667, '#5A595C'),    # Medium gray (borders)
    (0.6667, 0.8333, '#3E3D40'), # Dark gray (inputs)
    (0.8333, 1, '#2D2A2E')       # Darkest gray (background)
]
            for start, end, color in sections:
                theta = np.linspace(start_angle + start * (end_angle - start_angle),
                                    start_angle + end * (end_angle - start_angle), 500)
                r = np.ones_like(theta)
                ax.fill_between(theta, 0, r, color=color, alpha=0.5)

            # outer black line
            theta = np.linspace(start_angle, end_angle, 500)
            r = np.ones_like(theta)
            ax.plot(theta, r, color='black', lw=2)

            # draw the needle
            ax.plot([start_angle, angle], [0, 0.9], color='black', lw=3)

            # add numbers to the gauge
            for value in range(0, 1100, 100):
                theta = start_angle + (value / max_value) * (end_angle - start_angle)
                ax.text(theta, 1.1, str(value), horizontalalignment='center', verticalalignment='center', fontsize=8, color='black')

            # set the limits for the polar plot to the top half only
            ax.set_ylim(0, 1)
            ax.set_xlim(start_angle, end_angle)

            ax.grid(False)
            ax.set_yticks([])
            ax.set_xticks([])

            # Remove polar labels
            ax.set_theta_zero_location('N')
            ax.set_theta_direction(-1)

            # Embed Matplotlib figure into QGraphicsView
            canvas = FigureCanvas(fig)
            canvas.setStyleSheet("background: transparent;")  # Set transparent background for canvas
            scene = QGraphicsScene()
            scene.addWidget(canvas)
            self.ui.graphicsView_2.setScene(scene)
            self.ui.graphicsView_2.setStyleSheet("background: transparent;")
            self.ui.graphicsView_2.show()
            plt.close(fig)
            
        except Exception as e:
            tb=traceback.format_exc()
            print(tb)
            print(f"Error drawing gauge: {e}")

    def put_packet_in_queue(self, packet):
        try:
            global packetInput
            if packetInput == 0:
                self.qued_packets.append(packet)
                self.recently_qued_packets+=1
            if packetInput == 1:
                self.recently_qued_packets+=1
                self.qued_packets.append(packet)            
        except Exception as e:
            print(f"Error putting packet in queue: {e}")
    def updateBlacklist(self, f):
        try:
            ip = self.ui.lineEdit_6.text().strip()
            if(f == 1):
                self.blacklist.append(ip)
                self.block_ip(ip)
                self.networkLog+="Blocked IP: "+ip+"\n"
                
            else:
                self.blacklist.remove(ip)
                self.unblock_ip(ip)
                self.networkLog+="Unblocked IP: "+ip+"\n"
               

            model = QStringListModel()
            model.setStringList(self.blacklist)
            self.ui.listView_4.setModel(model)
        except Exception as e:
            print(f"Error updating blacklist: {e}")
    def Update_Network_Summary(self):
        try:
            self.list_of_activity.clear()
            for packet in self.qued_packets:
                if packet.haslayer(HTTPRequest):
                    host = packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else "Unknown"
                    path = packet[HTTPRequest].Path.decode() if packet[HTTPRequest].Path else "Unknown"

                    newnetworkactivity = NetworkActivity()
                    
                    
                    packet_time = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")

                    newnetworkactivity.activity = f"{packet_time} | HTTP Request: {host}{path}"
                    newnetworkactivity.mac_of_device = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
            
                    self.list_of_activity.append(newnetworkactivity)

                elif packet.haslayer(DNS) and packet[DNS].qr == 0:  # check for DNS queries
                    domain = packet[DNS].qd.qname.decode() if packet[DNS].qd.qname else "Unknown"

                    
                    newnetworkactivity = NetworkActivity()
                    
                    packet_time = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")

                    newnetworkactivity.activity = f"{packet_time} | DNS Query: {domain}"
                    newnetworkactivity.mac_of_device = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                    
                    
                    self.list_of_activity.append(newnetworkactivity)
                

        except Exception as e:
            print(f"Error updating network summary: {e}")
    def decode_packet(self, row, column):
         
        try:
             
            if not self.filterapplied:  
                packet = self.packets[row]
                
                # get the raw content of the packet
                raw_content = bytes(packet)
                
                # Prepare the formatted content with hex and ASCII
                formatted_content = []
                for i in range(0, len(raw_content), 16):  # Process 16 bytes per line
                    chunk = raw_content[i:i + 16]
                    
                    # Hexadecimal representatio
                    hex_part = " ".join(f"{byte:02x}" for byte in chunk)
                    
                    # ASCII representation (printable characters or dots for non-printable ones)
                    ascii_part = "".join(
                        chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
                    )
                    
            
                    formatted_content.append(f"{hex_part:<48}  {ascii_part}")
                
        
                model = QStringListModel()
                model.setStringList(formatted_content)
                self.ui.listView_2.setModel(model)
        except Exception as e:
            print(f"Error displaying packet content with ASCII: {e}")
    def Packet_Statistics(self):

        try:
            
            total_packets = len(self.packets)
        
            self.packet_statics = {
                "total": total_packets,
                "tcp": self.tot_tcp_packets,
                "udp": self.tot_udp_packets,
                "icmp": self.tot_icmp_packets,
                "dns": self.packet_stats.get("dns", 0),
                "http": self.packet_stats.get("http", 0),
                "https": self.packet_stats.get("https", 0),
                "telnet": self.packet_stats.get("telnet", 0),
                "ftp": self.packet_stats.get("ftp", 0),
            }
            
            packet_values = [self.tot_tcp_packets, self.tot_udp_packets, self.tot_icmp_packets, self.packet_stats.get("dns", 0), self.packet_stats.get("http", 0), self.packet_stats.get("https", 0), self.packet_stats.get("telnet", 0), self.packet_stats.get("ftp", 0)]
            packet_mean = mean(packet_values)
            packet_range = max(packet_values) - min(packet_values)
            packet_mode = mode(packet_values) if len(set(packet_values)) > 1 else "No Mode"  #  single-value case
            packet_stdev = stdev(packet_values) if len(packet_values) > 1 else 0
            
            formatted_content = [
                f"Total Packets: {self.packet_statics['total']}",
                f"TCP Packets: {self.packet_statics['tcp']}",
                f"UDP Packets: {self.packet_statics['udp']}",
                f"ICMP Packets: {self.packet_statics['icmp']}",
                f"DNS Packets: {self.packet_statics['dns']}",
                f"HTTP Packets: {self.packet_statics['http']}",
                f"HTTPS Packets: {self.packet_statics['https']}",
                f"Telnet Packets: {self.packet_statics['telnet']}",
                f"FTP Packets: {self.packet_statics['ftp']}",
                "Statistical Metrics:",
            f"Mean: {packet_mean:.2f}",
            f"Range: {packet_range}",
            f"Mode: {packet_mode}",
            f"Standard Deviation: {packet_stdev:.2f}",
            ]

            
            model = QStringListModel()
            model.setStringList(formatted_content)
            self.ui.listView_3.setModel(model)

        except Exception as e:
            print(f"Error in Packet_Statistics function: {e}")

    def change_chart(self,index):#function for changing beteen guage and donut chart
        if index==1:
            self.typeOFchartToPlot=1
            self.sensor_obj.show_donut_chart()
        else:
            self.typeOFchartToPlot=0

    def process_packet(self):
        try:
            global packetInput
            if packetInput == 0:
                packet = self.qued_packets[self.process_packet_index] 
            if packetInput == 1:
                packet = self.qued_packets[self.pcap_process_packet_index]
            timestamp = float(packet.time)
            readable_time = datetime.fromtimestamp(timestamp).strftime("%I:%M:%S %p")
            src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
            # extract port information for TCP/UDP
            sport = None
            dport = None
            if packet.haslayer("TCP"):
                self.packet_stats["tcp"] += 1
                self.tot_tcp_packets += 1
                sport = packet["TCP"].sport
                dport = packet["TCP"].dport
            elif packet.haslayer("UDP"):
                self.packet_stats["udp"] += 1
                self.tot_udp_packets += 1
                sport = packet["UDP"].sport
                dport = packet["UDP"].dport
            elif packet.haslayer("ICMP"):
                self.packet_stats["icmp"]+=1
            if src_ip in self.blacklist or dst_ip in self.blacklist or dport in self.blocked_ports:
                row_position = self.ui.tableWidget.rowCount()
                
                self.ui.tableWidget.insertRow(row_position)
                self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem("Blocked"))
                self.ui.tableWidget.setItem(row_position, 10, QTableWidgetItem("Blocked"))
               # if src_ip in self.blacklist:
                 #   self.block_ip(src_ip)
                #else:
                    #self.block_ip(dst_ip)
            else:
                self.packets.append(packet)
                if len(self.packets) >=15000:
                    removed_elements = self.packets[0:5000]
                    del self.qued_packets[0:5000]
                    del self.packets[0:5000]
                    self.process_packet_index -= 5000
                    for key in list(window.time_series.keys())[:2000]:
                        del window.time_series[key]
                    wrpcap("packet_file" + str(self.packetfile) + ".pcap", removed_elements)
                    removed_elements.clear()
                    self.packetfile += 1
                self.verify_packet_checksum(packet)
                
                protocol = self.get_protocol(packet)
                if protocol == "icmp":
                    self.tot_icmp_packets += 1
                islocal=False
                islocal=self. is_local_ip(src_ip)
                if islocal==True:
                    self.total_inside_packets+=1
                    self.local_packets.append(packet)
                else:
                    self.total_outside_packets+=1
                
                macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
            
                packet_length = int(len(packet))

            # 3xtract IP version
                ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                packet_length = int(len(packet))
                layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                self.packet_stats["total"] += 1
                if protocol == "tcp":
                    self.packet_stats["tcp"] += 1
                elif protocol== "udp":
                    self.packet_stats["udp"] += 1
                elif protocol == "icmp" or layer=="icmp":
                    self.packet_stats["icmp"] += 1
                elif protocol == "dns":
                    self.packet_stats["dns"] += 1
                elif protocol == "dhcp":
                    self.packet_stats["dhcp"] += 1
                elif protocol == "http":
                    self.packet_stats["http"] += 1
                elif protocol == "https":
                    self.packet_stats["https"] += 1
                elif protocol == "ftp":
                    self.packet_stats["ftp"] += 1
                elif protocol=="telnet":
                    self.packet_stats["telnet"] += 1
                else:
                    self.packet_stats["other"] += 1
                
                
                if self.filterapplied:
                    return
                elif self.sensor_obj.senFlag == 1 or self.sensor_obj.singleSenFlag == 1:
                    pass
                elif self.application_filter_flag==True:
                    pass
                else:
                    if self.capture == 1:
                        self.ui.label_6.setStyleSheet("background-color: Red;")
                        self.captured_packets.append(packet)
                    else:
                        self.ui.label_6.setStyleSheet("QLabel {\n"
                            "    color: white;\n"
                            "}\n"
                            "")
                    self.new_packet_features.append([packet_length, timestamp, protocol])
                    if (src_ip, dst_ip) in self.snort_alerts:
                        self.anomalies.append(packet)
                        current_time = datetime.now().strftime("%H:%M:%S")
                        self.networkLog+=current_time+"/  "+"An anomaly occured"+"\n"
                        row_position = self.ui.tableWidget_4.rowCount()
                        self.ui.tableWidget_4.insertRow(row_position)
                        self.ui.tableWidget_4.setItem(row_position, 0, QTableWidgetItem(readable_time))
                        self.ui.tableWidget_4.setItem(row_position, 1, QTableWidgetItem(src_ip))
                        self.ui.tableWidget_4.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                        self.ui.tableWidget_4.setItem(row_position, 3, QTableWidgetItem(str(self.snort_alerts[(src_ip, dst_ip)][0])))
                    row_position = self.ui.tableWidget.rowCount()
                    self.ui.tableWidget.insertRow(row_position)
                    self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(readable_time))
                    self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem(src_ip))
                    self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                    self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(protocol))
                    self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(layer))
                    
                    self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(macsrc))
                    self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(macdst))
                    self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem(str(sport) if sport else "N/A"))
                    self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(dport) if dport else "N/A"))
                    self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(packet_length)))
                    self.ui.tableWidget.setItem(row_position, 10, QTableWidgetItem(ip_version))
            if packetInput == 0:
                    
                    if self.process_packet_index < len(self.qued_packets) :
                        
                        self.process_packet_index+=1
            if packetInput == 1:
                    
                    if self.pcap_process_packet_index < len(self.qued_packets) :

                        self.pcap_process_packet_index+=1
                
            window.time_series[timestamp] = len(self.packets)

            if len(self.bandwidth_data) == 0 or self.bandwidth_data[-1][0] != readable_time:
                self.bandwidth_data.append((readable_time, len(packet)))
            else:
                self.bandwidth_data[-1] = (readable_time, self.bandwidth_data[-1][1] + len(packet))

        except Exception as e:
            print(f"Error processing packet: {e}")
            tb = traceback.format_exc()
            print("Traceback details:")
            print(tb)
    def verify_packet_checksum(self,packet):
        try:
            # check if the packet has a checksum field
            if hasattr(packet, 'chksum'):
                
                original_checksum = packet.chksum
                
                
                #  force  to recalculate the checksum by setting it to none(has to be that way for some reason)
                packet.chksum = None
                recalculated_checksum = raw(packet)  # Access raw data to trigger checksum calculation
                recalculated_packet = packet.__class__(recalculated_checksum)
                
            
                recalculated_checksum = recalculated_packet.chksum
                if original_checksum == recalculated_checksum:
                   
                    return False
                else:
                    self.corrupted_packet.append(packet)
                    current_time = datetime.now().strftime("%H:%M:%S")
                    self.networkLog+=current_time+"/  "+"A packet has been corrupted"+"\n"
                    return True
            else:
                return False
               
               
        except Exception as e:
            print(f"Error verifying checksum: {e}")
            return None
    def get_protocol(self, packet):
        try:
            #  common http and https ports for protocols
            http_ports = [80, 8080, 8888,5988]  
            https_ports = [443, 8443, 9443,5989]  

            
            if hasattr(packet, 'sport') and hasattr(packet, 'dport'): 
                sport = packet.sport
                dport = packet.dport
                if dport in http_ports or sport in http_ports:
                    return "http"
                elif dport in https_ports or sport in https_ports:
                    return "https"

            if packet.haslayer("IP"):
                ip_proto = packet["IP"].proto
                if ip_proto == 17:  # UDP protocol
                    if packet.haslayer("UDP"):
                        sport = packet["UDP"].sport
                        dport = packet["UDP"].dport
                        if dport == 53 or sport == 53:
                            return "dns"
                        elif dport in [67, 68] or sport in [67, 68]:
                            return "dhcp"
                        else:
                            return "udp"
                elif ip_proto == 6:  # TCP protocol
                    if packet.haslayer("TCP"):
                        sport = packet["TCP"].sport
                        dport = packet["TCP"].dport
                        if dport == 21 or dport == 20:
                            return "ftp"
                        elif dport == 23 or dport == 23:
                            return "telnet"
                        else:
                            return "tcp"
                elif ip_proto == 1:  # ICMP protocol
                    return "icmp"
                else:
                    return "Other"
            elif packet.haslayer("UDP"):  # check UDP layers for DNS/DHCP outside IP layer
                dport = packet["UDP"].dport
                sport = packet["UDP"].sport
                if dport == 53 or sport == 53:
                    return "dns"
                elif dport in [67, 68] or sport in [67, 68]:
                    return "dhcp"
                else:
                    return "udp"
            else:
                return "Other"  
        except Exception as e:
            print(f"Error getting protocol: {e}")
            return "N/A"


    def display_log(self):
        try:
                detailslist = self.networkLog.split("\n")
                model = QStringListModel()
                model.setStringList(detailslist)
                self.ui.listView_5.setModel(model)
        except Exception as e:
            print(f"Error displaying log: {e}")
    def save_log_to_file(self):
        try:
            with open("network_log.txt", "w", encoding="utf-8") as log_file:
                log_file.write(self.networkLog)
            print("Log saved successfully to 'network_log.txt'.")
        except Exception as e:
            print(f"Error saving log to file: {e}")

    def display_packet_details(self, row, column):
        try:
            if self.filterapplied==False:
                 packet = self.packets[row]
                 details = packet.show(dump=True)  # get packet details as a string
                 detailslist = details.split("\n")
                 model = QStringListModel()
                 model.setStringList(detailslist)
                 self.ui.listView.setModel(model)
                        
            if self.filterapplied==True:
                packet = self.filtered_packets[row]
                details = packet.show(dump=True)  # get packet details as a string
                detailslist = details.split("\n")
                model = QStringListModel()
                model.setStringList(detailslist)
                self.ui.listView.setModel(model)
        except Exception as e:
            print(f"Error displaying packet details: {e}")
    def is_local_ip(self,ip):

        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private  # returns True for local IPs, False for outside
        except ValueError:
    
            return False  # handle invalid IP addresses
    def design_and_send_packet(self):
        try:
            
            dst_ip = self.ui.lineEdit_ip_dst.text()
            src_ip = self.ui.lineEdit_ip_source.text()
            protocol = self.ui.comboBox_protocol.currentText()

            
            if not dst_ip or not src_ip:
                print("Source and destination IPs must be specified.")
                return
            
            
            ip_layer = IP(src=src_ip, dst=dst_ip)
            
           
            if protocol == "TCP":
                transport_layer = TCP(dport=80)  # Example: HTTP port
                packet = ip_layer / transport_layer / "Hello TCP"
            elif protocol == "UDP":
                transport_layer = UDP(dport=53)  # Example: DNS port
                packet = ip_layer / transport_layer / "Hello UDP"
            elif protocol == "ICMP":
                packet = ip_layer / ICMP() / "Hello ICMP"
            elif protocol == "FTP":
                transport_layer = TCP(dport=21)  # FTP uses port 21
                packet = ip_layer / transport_layer / "FTP Packet"
            elif protocol == "HTTP":
                transport_layer = TCP(dport=80)  # HTTP uses port 80
                packet = ip_layer / transport_layer / "HTTP Packet"
            elif protocol == "HTTPS":
                transport_layer = TCP(dport=443)  # HTTPS uses port 443
                packet = ip_layer / transport_layer / "HTTPS Packet"
            
            elif protocol == "DNS":
                packet = ip_layer / UDP(dport=53) / DNS(rd=1, qd="example.com")  
            else:
                print("Unsupported protocol selected.")
                return
            # Send the packet
            send(packet, verbose=False)
        except Exception as e:
            print(f"Error sending packet: {e}")
    def apply_filter(self):
        try:
            
            protocol_filters = {
                "udp": self.ui.checkBox.isChecked(),
                "tcp": self.ui.checkBox_2.isChecked(),
                "icmp": self.ui.checkBox_3.isChecked(),
                "dns": self.ui.checkBox_4.isChecked(),
                "dhcp": self.ui.checkBox_9.isChecked(),
                "http": self.ui.checkBox_5.isChecked(),
                "https": self.ui.checkBox_6.isChecked(),
                "telnet": self.ui.checkBox_7.isChecked(),
                "ftp": self.ui.checkBox_8.isChecked(),
                "Other": self.ui.checkBox_10.isChecked(),
            }
            
            self.ui.tableWidget.setRowCount(0)
            # check if all protocol filters are unchecked and both src and dst filters are empty
            src_filter = self.ui.lineEdit_2.text().strip()
            dst_filter = self.ui.lineEdit_5.text().strip()
            port_filter=self.ui.lineEdit.text().strip()
            stime = self.ui.dateTimeEdit.dateTime().toSecsSinceEpoch()
            etime = self.ui.dateTimeEdit_2.dateTime().toSecsSinceEpoch()

                #  heck if all protocol filters are unchecked and both src and dst filters are empty
            if not any(protocol_filters.values()) and not src_filter and not dst_filter and not port_filter and stime == 946677600 and etime == 946677600:
                    print("No protocols selected, and both source and destination filters are empty.")
                    self.ui.tableWidget.setRowCount(0)
                    self.helperboi()
                    self.filterapplied=False
                    
                    return  
                #
            self.filterapplied = True

            # the checked protocols
            selected_protocols = [protocol for protocol, checked in protocol_filters.items() if checked]
            
            src_filter = self.ui.lineEdit_2.text().strip()
            dst_filter = self.ui.lineEdit_5.text().strip()
            port_filter=self.ui.lineEdit.text().strip()
            
            combo_selection = self.ui.comboBox.currentText()  # 'Inside' or 'Outside'
            # clear the table before adding filtered packets
            self.ui.tableWidget.setRowCount(0)

            
            self.filtered_packets = []
            if(self.sensor_obj.senFlag == -1):
                x = self.packets
            else:
                x = self.sensor_obj.sensor_packet
            
            for packet in x:
                src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                protocol = self.get_protocol(packet)

             
                src_is_local = self.is_local_ip(src_ip)
                dst_is_local = self.is_local_ip(dst_ip)

                
                layer = (
                        "udp" if packet.haslayer("UDP") 
                        else "tcp" if packet.haslayer("TCP") 
                        else "icmp" if packet.haslayer("ICMP") 
                        else "N/A"
                    )
                protocol_match = protocol in selected_protocols if selected_protocols else True
                if "udp" in selected_protocols and layer == "udp":
                 
                 protocol_match = True
                elif "tcp" in selected_protocols and layer == "tcp":
                    protocol_match = True
                elif "icmp" in selected_protocols and layer == "icmp":
                    protocol_match = True
                elif "other" in selected_protocols and layer=="other":
                    protocol_match=True
                

                
                packet_time = datetime.fromtimestamp(float(packet.time))
                stime_match = True if stime == 946677600 or stime <= packet.time else False
                etime_match = True if etime == 946677600 or etime >= packet.time else False
                

                src_match = src_filter in src_ip if src_filter else True
                dst_match = dst_filter in dst_ip if dst_filter else True

                
                if combo_selection == "Inside":
                    ip_match = src_is_local and dst_is_local
                elif combo_selection == "Outside":
                    ip_match = not src_is_local or not dst_is_local
                else:
                    ip_match = True  #  no filter based on inside/outside by deafult
                sport = None
                dport = None
                port_filter=self.ui.lineEdit.text().strip()
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                port_match = True  
                if port_filter!="":
                    port_filter = int(port_filter)
                    if sport == port_filter or dport == port_filter:
                        port_match = True
                    else:
                        port_match = False
                
                
                if protocol_match and src_match and dst_match and ip_match and port_match and stime_match and etime_match:

                    self.filtered_packets.append(packet)
                    macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                    macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                    
                    packet_length = int(len(packet))

                
                    ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                    layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                    
                    
                    
                    row_position = self.ui.tableWidget.rowCount()
                    
                    self.ui.tableWidget.insertRow(row_position)
                    self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")))
                    self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem(src_ip))
                    self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                    self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(protocol))
                    self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(layer))
                   
                    self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(macsrc))
                    self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(macdst))
                    self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem(str(sport) if sport else "N/A"))
                    self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(dport) if dport else "N/A"))
                    self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(packet_length)))
                    self.ui.tableWidget.setItem(row_position, 10, QTableWidgetItem(ip_version))
            #self.apply_filter=False
        except Exception as e:
            print(f"Error processing packet: {e}")    
    #end of filter
    def helperboi(self):#for rebuilding the packets
                try:
                    
                    x = self.packets
                    for packet in x:
                        src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                        dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                        protocol = self.get_protocol(packet)
                        
                        layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                        
                        packet_time = datetime.fromtimestamp(float(packet.time))
                        macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                        macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                        
                        packet_length = int(len(packet))

                    
                        ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                        layer = "udp" if packet.haslayer("UDP") else "tcp" if packet.haslayer("TCP") else "Other"
                       
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
                        self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(protocol))
                        self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(layer))
                       
                        self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(macsrc))
                        self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(macdst))
                        self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem(str(sport) if sport else "N/A"))
                        self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(dport) if dport else "N/A"))
                        self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(packet_length)))
                        self.ui.tableWidget.setItem(row_position, 10, QTableWidgetItem(ip_version))
                except:
                    print("fr")
    
class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(object)
    readPackets = []

    def run(self):
        try:
            global packetInput, packetFile, packetIndex
            
            print(packetInput)
            print("GOOGOO")
            match packetInput:
                case 0:
                    sniff(prn=self.emit_packet,promisc=True, store=False, stop_filter=lambda _: packetInput != 0)
                case 1:
                    try:
                        packets = rdpcap(packetFile)
                        
                        for packet in packets:
                            
                            self.packet_captured.emit(packet)
                    except Exception as e:
                        print(f"Error reading pcap file: {e}")
                case 2:
                    try:
                        self.readPackets = pd.read_csv(packetFile)
                        for _, row in self.readPackets.iterrows():
                            self.packet_captured.emit(row)
                    except Exception as e:
                        print(f"Error reading CSV file: {e}")
        except Exception as e:
            print(f"Error in run function: {e}")

    def emit_packet(self, packet):
        self.packet_captured.emit(packet)
        
class Naswail(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.showMaximized()
        self.setWindowTitle("Naswail - Main")

        global packetInput, clearRead
        
        self.filterapplied=False
        #
        self.typeOFchartToPlot=0#0 represents the guage charrt while 1 represents the donut chart
        self.pushButton.clicked.connect(self.resetfilter)
        self.packets = []
        self.times = []
        self.counts = []
        self.capture = -1
        self.start_time = QTime.currentTime()
        self.elapsedTime = 0
        self.scene = QGraphicsScene(self)
        self.total_inside_packets=0
        self.total_outside_packets=0
        self.time_series = {}
        #objects
        self.secondary_widget3=None
        self.PacketSystemobj = PacketSystem(self)
        self.SensorSystemobj = SensorSystem(self)
        self.Appsystemobj = ApplicationsSystem(self)
    
        self.SensorSystemobj.set_packet_system(self.PacketSystemobj)
        self.PacketSystemobj.set_sensor_system(self.SensorSystemobj)
        self.Appsystemobj.set_packet_system(self.PacketSystemobj)
        #
        self.PacketSystemobj.draw_gauge()
        #Logo Image
        pixmap = QPixmap(r"logo.png")
        self.pixmap_item = QGraphicsPixmapItem(pixmap)
        self.scene.addItem(self.pixmap_item)
        self.graphicsView.setScene(self.scene)
        self.graphicsView.setFixedSize(71, 61)
        self.graphicsView.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self.tableWidget.setColumnCount(10)
        self.tableWidget.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Protocol","layer","macsrc","macdst","srcport","dstport","length","IP version"])
        self.tableWidget.cellClicked.connect(self.PacketSystemobj.display_packet_details)
        self.tableWidget.cellClicked.connect(self.PacketSystemobj.decode_packet)
        self.tabWidget.currentChanged.connect(lambda index: self.PacketSystemobj.change_chart(1) if index == 2 else self.PacketSystemobj.change_chart(0))
        self.tabWidget.currentChanged.connect(lambda index: self.Appsystemobj.get_applications_with_ports() if index == 3 else None)
        self.tabWidget.currentChanged.connect(lambda index: self.PacketSystemobj.Packet_Statistics() if index == 5 else None)
        self.tabWidget.currentChanged.connect(lambda index: self.PacketSystemobj.display_log() if index == 7 else None)
        self.tableWidget_2.setColumnCount(2)
        self.tableWidget_2.setHorizontalHeaderLabels(["Name", "IP"])
        self.tableWidget_2.cellClicked.connect(self.SensorSystemobj.filter_sensors)
        self.tableWidget_3.setColumnCount(5)
        self.tableWidget_3.setHorizontalHeaderLabels(["Port", "Application", "IP","CPU","Memory-percent"])
        self.tableWidget_3.cellClicked.connect(self.Appsystemobj.analyze_app)
        self.tableWidget_4.setColumnCount(4)
        self.tableWidget_4.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Attack Type"])
        #self.tableWidget_4.cellClicked.connect(self.Appsystemobj.analyze_app)
        self.pushButton_5.clicked.connect(self.toggleCapture)
        self.pushButton_6.clicked.connect(self.toggleCapture)
        self.pushButton_7.clicked.connect(self.SensorSystemobj.toggleSenFlag)
        self.actionImport_Packets.triggered.connect(self.import_file)
        self.actionExport_Packets.triggered.connect(self.export_packets)
        self.actionLive_Capture.triggered.connect(self.resetInput)
        self.buttonBox_2.clicked.connect(lambda _: self.SensorSystemobj.updateSensor(1))
        self.buttonBox_2.rejected.connect(lambda _: self.SensorSystemobj.updateSensor(2))
        self.pushButton_10.clicked.connect(lambda _: self.PacketSystemobj.updateBlacklist(1))
        self.pushButton_11.clicked.connect(lambda _: self.PacketSystemobj.updateBlacklist(2))
        self.pushButton_12.clicked.connect(lambda _:self.PacketSystemobj.save_log_to_file())
        self.pushButton_apply.clicked.connect(self.PacketSystemobj.design_and_send_packet)
       
        self.checkBox.stateChanged.connect(self.PacketSystemobj.apply_filter)      # UDP
        self.checkBox_2.stateChanged.connect(self.PacketSystemobj.apply_filter)    # TCP
        self.checkBox_3.stateChanged.connect(self.PacketSystemobj.apply_filter)    # ICMP
        self.checkBox_4.stateChanged.connect(self.PacketSystemobj.apply_filter)    # DNS
        self.checkBox_5.stateChanged.connect(self.PacketSystemobj.apply_filter)    # DHCP
        self.checkBox_6.stateChanged.connect(self.PacketSystemobj.apply_filter)    # HTTP
        self.checkBox_7.stateChanged.connect(self.PacketSystemobj.apply_filter)    # HTTPS
        self.checkBox_8.stateChanged.connect(self.PacketSystemobj.apply_filter)    # TELNET
        self.checkBox_9.stateChanged.connect(self.PacketSystemobj.apply_filter)    # FTP
        self.checkBox_10.stateChanged.connect(self.PacketSystemobj.apply_filter)   # Other
        self.pushButton_9.clicked.connect(self.PacketSystemobj.apply_filter)
        self.dateTimeEdit.setDisplayFormat("dd-MMM-yyyy hh:mm AP")  
        self.dateTimeEdit_2.setDisplayFormat("dd-MMM-yyyy hh:mm AP")  
        self.sniffer_thread = PacketSnifferThread()
        self.sniffer_thread.packet_captured.connect(self.PacketSystemobj.put_packet_in_queue)
        self.sniffer_thread.start()
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.tick)

        self.num=100
      
        self.stats_timer.start(10 )
        self.packet_per_seconds_timer = QTimer()
        self.packet_per_seconds_timer.timeout.connect(self.ppsttick)
        self.packet_per_seconds_timer.start(1000)
        self.ct = 0
        self.pushButton_2.clicked.connect(self.open_analysis)
        self.pushButton_3.clicked.connect(self.open_tool)
        self.pushButton_13.clicked.connect(self.open_incidentresponse)
        #notifications
       
        self.notificationButton.clicked.connect(self.show_notifications)
        self.notificationList.itemClicked.connect(self.show_notification_details)
        details="ayad has a tendency to goof quite hard these days, so he is a bit busy"
        title="Ayad be goofing"
        full_details=""" come on man its too ez btruh i just like the way i fight children i hate kids ama kidnap them"""
        self.add_notification(title,details,full_details)
        
    def show_notifications(self):
    
        self.notificationMenu.exec(
        self.notificationButton.mapToGlobal(
        QtCore.QPoint(0, self.notificationButton.height())
        )
        )

    def show_notification_details(self, item):
        """Show detailed view of clicked notification"""
        # Get stored data
        notification_data = item.data(QtCore.Qt.ItemDataRole.UserRole)
        
        detail_dialog = QtWidgets.QDialog(parent=self.centralwidget)
        detail_dialog.setWindowTitle("Notification Details")
        detail_dialog.setFixedSize(400, 400)
        
        layout = QtWidgets.QVBoxLayout()
        
        detail_text = QtWidgets.QTextEdit()
        detail_text.setReadOnly(True)
        detail_text.setStyleSheet("""
            QTextEdit {
                background-color: #3E3D40;
                color: #FFFFFF;
                border: 1px solid #5A595C;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
            }
        """)
        
        # Set actual content from stored data
        detail_text.setText(f"""
        {notification_data.get('title', 'Notification')}
        
        Time: {notification_data.get('timestamp', 'Unknown')}
        Severity: {notification_data.get('severity', 'Medium')}
        
        Details:
        {notification_data.get('details', 'No details available')}
        
        Full Report:
        {notification_data.get('full_details', 'No additional information')}
        """)
        
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(detail_dialog.close)
        
        layout.addWidget(detail_text)
        layout.addWidget(close_btn)
        detail_dialog.setLayout(layout)
        detail_dialog.exec()

    def add_notification(self, title, details="", full_details=""):
        """Add notification with structured data"""
        item = QtWidgets.QListWidgetItem(title)
        
        # Store data as dictionary
        item.setData(QtCore.Qt.ItemDataRole.UserRole, {
            'title': title,
            'details': details,
            'full_details': full_details,
            'timestamp': QtCore.QDateTime.currentDateTime().toString(),
            'severity': 'High'  # Add your severity logic here
        })
    
        self.notificationList.addItem(item)
    def open_tool(self):
        try:
            self.secondary_widget2 = Window_Tools(self)
            self.hide()
            self.secondary_widget2.show()
        except Exception as e:
            print(f"Error in open_tool function: {e}")
    def open_analysis(self):
            try:

                self.secondary_widget = Window_Analysis(self)  
                self.hide()
                self.secondary_widget.show()
            except Exception as e:
                print(f"Error in open_analysis function: {e}")
                tb=traceback.format_exc()
                print(tb)

    def open_incidentresponse(self):
            try:
                if self.secondary_widget3==None:
                     self.secondary_widget3 = IncidentResponse(self)  
                self.hide()
                self.secondary_widget3.show()
            except Exception as e:
                print(f"Error in open_incidentresponse function: {e}")
                tb=traceback.format_exc()
                print(tb)
    def resetfilter(self):
        try:
            self.PacketSystemobj.draw_gauge()
            checkboxes = [
                self.checkBox,
                self.checkBox_2,
                self.checkBox_3,
                self.checkBox_4,
                self.checkBox_5,
                self.checkBox_6,
                self.checkBox_7,
                self.checkBox_8,
                self.checkBox_9,
                self.checkBox_10
            ]
            for checkbox in checkboxes:
                checkbox.setCheckState(Qt.CheckState.Unchecked)
            self.tableWidget.setRowCount(0)
            def helperboi():
                try:
                    
                    x = self.PacketSystemobj.packets
                    for packet in x:
                        src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                        dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                        protocol = self.PacketSystemobj.get_protocol(packet)
                        
                        layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                        
                        packet_time = datetime.fromtimestamp(float(packet.time))
                        macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                        macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                        
                        packet_length = int(len(packet))

                    
                        ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                        layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                       
                        sport = None
                        dport = None
                        if packet.haslayer("TCP"):
                            sport = packet["TCP"].sport
                            dport = packet["TCP"].dport
                        elif packet.haslayer("UDP"):
                            sport = packet["UDP"].sport
                            dport = packet["UDP"].dport
                        
                        row_position = self.tableWidget.rowCount()
                        
                        self.tableWidget.insertRow(row_position)
                        self.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")))
                        self.tableWidget.setItem(row_position, 1, QTableWidgetItem(src_ip))
                        self.tableWidget.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                        self.tableWidget.setItem(row_position, 3, QTableWidgetItem(protocol))
                        self.tableWidget.setItem(row_position, 4, QTableWidgetItem(layer))
                       
                        self.tableWidget.setItem(row_position, 5, QTableWidgetItem(macsrc))
                        self.tableWidget.setItem(row_position, 6, QTableWidgetItem(macdst))
                        self.tableWidget.setItem(row_position, 7, QTableWidgetItem(str(sport) if sport else "N/A"))
                        self.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(dport) if dport else "N/A"))
                        self.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(packet_length)))
                        self.tableWidget.setItem(row_position, 10, QTableWidgetItem(ip_version))
                except:
                    print("fr")
            
            helperboi()
            self.PacketSystemobj.filterapplied=False
            self.PacketSystemobj.typeOFchartToPlot=0
            self.PacketSystemobj.application_filter_flag=False
            self.SensorSystemobj.senFlag = -1 
            self.SensorSystemobj.singleSenFlag = -1
        except Exception as e:
            print(f"Error in resetfilter function: {e}")
    def ppsttick(self):
        try:
            self.PacketSystemobj.rate_of_packets=self.PacketSystemobj.recently_qued_packets/1
            if self.PacketSystemobj.rate_of_packets>=100 and  self.PacketSystemobj.rate_of_packets<=300:
                current_time = datetime.now().strftime("%H:%M:%S")
                self.PacketSystemobj.networkLog+=current_time+"/  "+"moderately high increase in packets"+"\n"
            if self.PacketSystemobj.rate_of_packets>=300 and  self.PacketSystemobj.rate_of_packets<=700:
                current_time = datetime.now().strftime("%H:%M:%S")
                self.PacketSystemobj.networkLog+=current_time+"/ "+" high increase in packets"+"\n"
            if self.PacketSystemobj.rate_of_packets>=700:
                current_time = datetime.now().strftime("%H:%M:%S")
                self.PacketSystemobj.networkLog+=current_time+"/  "+" Extremely high increase in packets"+"\n"
            self.PacketSystemobj.recently_qued_packets=0
            self.PacketSystemobj.draw_gauge()
        except Exception as e:
            print(f"Error in ppsttick function: {e}")
    def tick(self):
        try:
            current_time = QTime.currentTime()
            elapsed_seconds = self.start_time.secsTo(current_time)
            hours = elapsed_seconds // 3600
            minutes = (elapsed_seconds % 3600) // 60
            seconds = elapsed_seconds % 60
            self.elapsedTime = f"{hours:02}:{minutes:02}:{seconds:02}"
            self.label_6.setText(str(self.elapsedTime))
            global packetInput, packetFile, packetIndex
            if self.PacketSystemobj.process_packet_index<len(self.PacketSystemobj.qued_packets)and self.PacketSystemobj.pcap_process_packet_index<len(self.PacketSystemobj.qued_packets):
                self.PacketSystemobj.process_packet()
                self.PacketSystemobj.Packet_Statistics()
        except Exception as e:
            print(f"Error in tick function: {e}")

        
    def toggleCapture(self):
      
        self.capture *= -1
        self.PacketSystemobj.capture*=-1

    def import_file(self):
        
        try:
            global packetFile, packetInput

            packetFile, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files ();;PCAP Files (.pcap);;CSV Files (*.csv)")

            if packetFile:
                print(f"Selected file: {packetFile}")
                ext = os.path.splitext(packetFile)[1].lower()
                if ext == '.pcap':
                
                    packetInput=69#random number to stop sniffing until the below stuff is done
                    self.PacketSystemobj.process_packet_index=0
                    self.PacketSystemobj.pcap_process_packet_index=0
                    self.PacketSystemobj.packet_stats={"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0,"http":0,"https":0,"dns":0,"dhcp":0,"ftp":0,"telnet":0}
                    self.PacketSystemobj.tot_icmp_packets=0
                    self.PacketSystemobj.tot_tcp_packets=0
                    self.PacketSystemobj.tot_udp_packets=0
                    self.PacketSystemobj.packets.clear()
                    self.PacketSystemobj.qued_packets.clear()
                    self.PacketSystemobj.anomalies.clear()
                    self.tableWidget_4.setRowCount(0)
                    packetInput = 1        
                elif ext == '.csv':
                    packetInput = 2
                
                self.packets.clear()
                self.tableWidget.setRowCount(0)
                PacketSnifferThread.run(self.sniffer_thread)
            else:
                print("No file selected")
        except Exception as e:
            print(f"Error in import_file function: {e}")

    def export_packets(self):
        try:
            wrpcap("captured_packets.pcap", self.PacketSystemobj.captured_packets)
            print("Packets exported successfully.")
        except Exception as e:
            print(f"Error exporting packets: {e}")

    def resetInput(self):
        try:
            global packetIndex, packetInput, packetFile
            packetInput = 0
            self.PacketSystemobj.packets.clear()
            self.PacketSystemobj.qued_packets.clear()
            self.PacketSystemobj.process_packet_index=0
            self.PacketSystemobj.pcap_process_packet_index=0
            self.PacketSystemobj.anomalies.clear()
            self.tableWidget_4.setRowCount(0)
            packetFile = ""
            self.sniffer_thread.quit()  
            self.sniffer_thread.wait()  
            self.sniffer_thread.start() 
        except Exception as e:
            print(f"Error in resetInput function: {e}")
def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

def run_command_as_admin():
    # Command to execute
    cmd_command = 'snort -i 5 -c C:\\Snort\\etc\\snort.conf -l C:\\Snort\\log -A fast'
    
    # Run in a new persistent command prompt window
    subprocess.Popen(
        ['cmd.exe', '/k', cmd_command],
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )
 
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Create and show the splash screen
    splash = SplashScreen()
    splash.show()
    splash.start_progress()
    
    # Create the main window but don't show it yet
    window = Naswail()
    
    # Process events to ensure splash screen is shown
    app.processEvents()
    
    # Simulate loading delay
    def finish_loading():
        # Check admin privileges and run command if needed
        if is_admin():
            run_command_as_admin()
        
        # Close splash and show main window
        splash.finish(window)
        window.show()
        
        # Force the window to activate and come to the foreground
        window.activateWindow()
        window.raise_()
        
        # On Windows, this can help ensure the window comes to front
        if platform.system() == "Windows":
            # Set window as the foreground window
            hwnd = window.winId()
            try:
                ctypes.windll.user32.SetForegroundWindow(hwnd)
            except:
                pass
    
    # Use QTimer to transition from splash to main window
    QTimer.singleShot(3000, finish_loading)  # 3 seconds delay
    
    sys.exit(app.exec())
