import sys
import numpy as np
import pandas as pd
import time
import multiprocessing
import psutil
import os
import ipaddress
from sklearn.svm import OneClassSVM
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import QPainter, QPixmap
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from statistics import mean, median, mode, stdev, variance
from sklearn.model_selection import train_test_split, StratifiedShuffleSplit
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeClassifier, DecisionTreeRegressor
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import mean_squared_error, r2_score, accuracy_score
from sklearn.preprocessing import LabelEncoder
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib.patches import Wedge
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from scapy.layers.http import HTTPRequest  
from scapy.layers.inet import IP, TCP, UDP,ICMP
from scapy.layers.dns import DNS
import networkx as nx
from math import cos, sin, pi
from datetime import datetime, timedelta
from UI_Main import Ui_MainWindow
from Code_Analysis import Window_Analysis
from Code_Tools import Window_Tools

packetInput = 0
packetFile = None
clearRead = 0 
packetIndex = 0
class ApplicationsSystem:
    def __init__(self, ui_main_window):
        self.ui = ui_main_window
        self.apps = dict()
        self.packet_obj = None  # Delay initialization
    def set_packet_system(self, packet_obj):
        """Set the packet system after both are initialized."""
        self.packet_obj = packet_obj
    def get_applications_with_ports(self):
        apps_with_ports = []

        for proc in psutil.process_iter(attrs=['pid', 'name', 'status','cpu_percent', 'memory_percent']):
            try:
                pid = proc.info['pid']
                app_name = proc.info['name']
               
                app_status = proc.info['status']
                app_cpu=proc.info['cpu_percent']
                app_mem=proc.info['memory_percent']

                connections = psutil.Process(pid).net_connections(kind='inet')
                for conn in connections:
                    local_ip, local_port = conn.laddr
                    apps_with_ports.append({
                        "Application": app_name,
                        "IP": local_ip,
                        "Port": local_port,
                     
                        "Status": app_status,
                        "CPU": app_cpu,
                        "Memory": app_mem
                    })
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


    def analyze_app(self, row):
        try:
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
                layer = "udp" if packet.haslayer("UDP") else "tcp" if packet.haslayer("TCP") else "N/A"
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
        self.sen_info = []
        self.sensor_packet = []
        self.sensors_name = []
        self.senFlag = -1
        self.singleSenFlag = -1
        self.sen_ct = 0
        self.packet_obj = None  # Delay initialization
        self.ct_sensor_packet=[]    
        self.sensors = {}
        

    def set_packet_system(self, packet_obj):
        """Set the packet system after both are initialized."""
      
       
        self.packet_obj = packet_obj
    
    def filter_sensors(self, row, col):

        try:
            
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
                    layer = "udp" if packet.haslayer("UDP") else "tcp" if packet.haslayer("TCP") else "N/A"

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
            # Data for the chart
            sizes = [1]  # Percentages
            labels = ['']  # Empty labels to hide text
            s=0
            for s in range(len(self.sensors)):
                sizes.append(s)
                labels.append('')
            #end of for
            colors = ['#ff4d4d', '#3399ff', '#33ff33']  # Custom colors
            
            # Create the figure and axes
            fig, ax = plt.subplots(figsize=(6, 6))  # Set size of the figure
            
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
        try:
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
class NetworkActivity:
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
        self.tot_tcp_packets = 0
        self. tot_udp_packets = 0
        self.tot_icmp_packets = 0
        self.rate_of_packets=0
        self.recently_qued_packets=0
        self.typeOFchartToPlot=0
        self.packetfile = 1
        #machine learning stuff
        self.le = LabelEncoder()
        self.train = pd.read_csv('TrainATest2.csv', low_memory=False)
       # self.test = pd.read_csv('Simulation.csv', low_memory=False)
        self.X_train, self.y_train, self.X_test, self.y_test = self.encode(self.train)
        self.classes = self.train.columns[:-1].to_numpy()
        self.anmodel = RandomForestClassifier()
        self.anmodel.fit(self.X_train, self.y_train)
        self.train_predictions = self.anmodel.predict(self.X_test)
        acc = accuracy_score(self.y_test, self.train_predictions)
        print("Accuracy: {:.4%}".format(acc))
        self.list_of_activity=[]
        ##############

    def set_sensor_system(self, sensor_obj):
        """Set the sensor system after both are initialized."""
        self.sensor_obj = sensor_obj
    def draw_gauge(self):
        if self.sensor_obj.senFlag == 1 or self.sensor_obj.singleSenFlag == 1:
            self.typeOFchartToPlot=1
            
        if self.typeOFchartToPlot == 1:
            self.ui.graphicsView_2.setScene(None)
            self.sensor_obj.show_donut_chart()
            return

        # Clear the existing scene in graphicsView_2
        view_width = self.ui.graphicsView_2.width()
        view_height = self.ui.graphicsView_2.height()

        # Calculate the figure size based on the graphics view size (in inches, assuming 100 DPI)
        dpi = 100
        fig_width = view_width / dpi
        fig_height = view_height / dpi

        # Create a Matplotlib figure with the calculated size
        fig = Figure(figsize=(fig_width, fig_height), dpi=dpi)
        ax = fig.add_subplot(111, polar=True)

        # Make the background transparent
        fig.patch.set_alpha(0)  # Transparent figure background
        ax.set_facecolor("none")  # Transparent axis background

        # Gauge chart settings
        start_angle = -np.pi / 2  # Start angle (90 degrees counter-clockwise)
        end_angle = np.pi / 2     # End angle (90 degrees clockwise)

        # Define the range and current value
        min_value = 0
        max_value = 1000
        current_value = max(min(self.rate_of_packets, max_value), min_value)  # Clamp value between 0 and 1000

        # Compute the needle angle
        angle = start_angle + (current_value / max_value) * (end_angle - start_angle)

        # Draw the gauge sections with colors
        sections = [
            (0, 0.1667, 'lightskyblue'),
    (0.1667, 0.3333, 'deepskyblue'),
    (0.3333, 0.5, 'dodgerblue'),
    (0.5, 0.6667, 'blue'),
    (0.6667, 0.8333, 'mediumblue'),
    (0.8333, 1, 'darkblue')
        ]
        for start, end, color in sections:
            theta = np.linspace(start_angle + start * (end_angle - start_angle),
                                start_angle + end * (end_angle - start_angle), 500)
            r = np.ones_like(theta)
            ax.fill_between(theta, 0, r, color=color, alpha=0.5)

        # Draw the gauge arc (only the top half)
        theta = np.linspace(start_angle, end_angle, 500)
        r = np.ones_like(theta)
        ax.plot(theta, r, color='black', lw=2)

        # Draw the needle
        ax.plot([start_angle, angle], [0, 0.9], color='black', lw=3)

        # Add numbers to the gauge
        for value in range(0, 1100, 100):
            theta = start_angle + (value / max_value) * (end_angle - start_angle)
            ax.text(theta, 1.1, str(value), horizontalalignment='center', verticalalignment='center', fontsize=8, color='black')

        # Set the limits for the polar plot to the top half only
        ax.set_ylim(0, 1)
        ax.set_xlim(start_angle, end_angle)

        # Remove grid and ticks
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
                
            else:
                self.blacklist.remove(ip)
               

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

                    # Create a new NetworkActivity instance
                    newnetworkactivity = NetworkActivity()
                    
                    # Format the timestamp
                    packet_time = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")

                    newnetworkactivity.activity = f"{packet_time} | HTTP Request: {host}{path}"
                    newnetworkactivity.mac_of_device = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                    # Append to the list
                    self.list_of_activity.append(newnetworkactivity)

                elif packet.haslayer(DNS) and packet[DNS].qr == 0:  # Check for DNS queries
                    domain = packet[DNS].qd.qname.decode() if packet[DNS].qd.qname else "Unknown"

                    # Create a new NetworkActivity instance
                    newnetworkactivity = NetworkActivity()
                    
                    # Format the timestamp
                    packet_time = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")

                    newnetworkactivity.activity = f"{packet_time} | DNS Query: {domain}"
                    newnetworkactivity.mac_of_device = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                    
                    # Append to the list
                    self.list_of_activity.append(newnetworkactivity)

        except Exception as e:
            print(f"Error updating network summary: {e}")
    def decode_packet(self, row, column):
         
        try:
             
            if not self.filterapplied:  # Check if the filter is not applied
                packet = self.packets[row]
                
                # Get the raw content of the packet
                raw_content = bytes(packet)
                
                # Prepare the formatted content with hex and ASCII
                formatted_content = []
                for i in range(0, len(raw_content), 16):  # Process 16 bytes per line
                    chunk = raw_content[i:i + 16]
                    
                    # Hexadecimal representation
                    hex_part = " ".join(f"{byte:02x}" for byte in chunk)
                    
                    # ASCII representation (printable characters or dots for non-printable ones)
                    ascii_part = "".join(
                        chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
                    )
                    
                    # Combine hex and ASCII parts
                    formatted_content.append(f"{hex_part:<48}  {ascii_part}")
                
                # Create a QStringListModel and set it to the listView_2
                model = QStringListModel()
                model.setStringList(formatted_content)
                self.ui.listView_2.setModel(model)
        except Exception as e:
            print(f"Error displaying packet content with ASCII: {e}")
    def Packet_Statistics(self):

        try:
            # Calculate packet statistics
            total_packets = len(self.packets)
            

            # Store statistics in a dictionary
            self.packet_statics = {
                "total": total_packets,
                "tcp": self.tot_tcp_packets,
                "udp": self.tot_udp_packets,
                "icmp": self.tot_icmp_packets,
            }
            
            packet_values = [self.tot_tcp_packets, self.tot_udp_packets, self.tot_icmp_packets]
            packet_mean = mean(packet_values)
            packet_range = max(packet_values) - min(packet_values)
            packet_mode = mode(packet_values) if len(set(packet_values)) > 1 else "No Mode"  # Handle single-value case
            packet_stdev = stdev(packet_values) if len(packet_values) > 1 else 0
            # Format the statistics for display
            formatted_content = [
                f"Total Packets: {self.packet_statics['total']}",
                f"TCP Packets: {self.packet_statics['tcp']}",
                f"UDP Packets: {self.packet_statics['udp']}",
                f"ICMP Packets: {self.packet_statics['icmp']}",
                "Statistical Metrics:",
            f"Mean: {packet_mean:.2f}",
            f"Range: {packet_range}",
            f"Mode: {packet_mode}",
            f"Standard Deviation: {packet_stdev:.2f}",
            ]

            # Update the list view with the formatted statistics
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
            if src_ip in self.blacklist or dst_ip in self.blacklist:
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
            else:
                self.packets.append(packet)
                if len(self.packets) >= 15000:
                    removed_elements = self.packets[0:4999]
                    del self.packets[0:4999]
                    wrpcap("packet_file" + str(self.packetfile) + ".pcap", removed_elements)
                    self.packetfile += 1
                self.verify_packet_checksum(packet)
                #self.Update_Network_Summary(packet)
                protocol = self.get_protocol(packet)
                if protocol == "icmp":
                    self.tot_icmp_packets += 1
                islocal=False
                islocal=self. is_local_ip(src_ip)
                if islocal==True:
                    self.total_inside_packets+=1
                else:
                    self.total_outside_packets+=1
                # Extract MAC addresses
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
                    self.packet_stats["ICMP"]+=1
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
                
                # Add to table
                
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
                    formattedPacket = self.packet_to_dataframe(packet, self.classes)
                    formattedPacket2 = self.encodePacket(formattedPacket)
                    anomalyCheck = self.anmodel.predict(formattedPacket2)
                    if(anomalyCheck.item()):
                        self.anomalies.append(packet)
                        current_time = datetime.now().strftime("%H:%M:%S")
                        self.networkLog+=current_time+"/  "+"An anomaly occured"+"\n"
                        row_position = self.ui.tableWidget_4.rowCount()
                        self.ui.tableWidget_4.insertRow(row_position)
                        self.ui.tableWidget_4.setItem(row_position, 0, QTableWidgetItem(readable_time))
                        self.ui.tableWidget_4.setItem(row_position, 1, QTableWidgetItem(src_ip))
                        self.ui.tableWidget_4.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                        self.ui.tableWidget_4.setItem(row_position, 3, QTableWidgetItem(protocol))
                    row_position = self.ui.tableWidget.rowCount()
                    self.ui.tableWidget.insertRow(row_position)
                    self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(readable_time))
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
            #print("Traceback details:")
           # print(tb)
    def verify_packet_checksum(self,packet):
        try:
            # Check if the packet has a checksum field
            if hasattr(packet, 'chksum'):
                # Extract the original checksum from the packet
                original_checksum = packet.chksum
                
                # Recalculate the checksum
                # Use `None` to force Scapy to recalculate the checksum
                packet.chksum = None
                recalculated_checksum = raw(packet)  # Access raw data to trigger checksum calculation
                recalculated_packet = packet.__class__(recalculated_checksum)
                
                # Compare the checksums
                recalculated_checksum = recalculated_packet.chksum
                if original_checksum == recalculated_checksum:
                   
                    return False
                else:
                    self.corrupted_packet.append(packet)
                    return True
            else:
                return False
               
               
        except Exception as e:
            print(f"Error verifying checksum: {e}")
            return None
    def get_protocol(self, packet):
        try:
            # Define common ports for protocols
            http_ports = [80, 8080, 8000, 8888,5988]  # Common HTTP ports
            https_ports = [443, 8443, 9443,5989]  # Common HTTPS ports

            # General checks for HTTP and HTTPS based on ports
            if hasattr(packet, 'sport') and hasattr(packet, 'dport'):  # Check if ports are available
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
            elif packet.haslayer("UDP"):  # Check UDP layers for DNS/DHCP outside IP layer
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
                 details = packet.show(dump=True)  # Get packet details as a string
                 detailslist = details.split("\n")
                 model = QStringListModel()
                 model.setStringList(detailslist)
                 self.ui.listView.setModel(model)
                        
            if self.filterapplied==True:
                packet = self.filtered_packets[row]
                details = packet.show(dump=True)  # Get packet details as a string
                detailslist = details.split("\n")
                model = QStringListModel()
                model.setStringList(detailslist)
                self.ui.listView.setModel(model)
        except Exception as e:
            print(f"Error displaying packet details: {e}")
    def is_local_ip(self,ip):
        """Check if an IP address is private (local)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private  # Returns True for private IPs, False otherwise
        except ValueError:
    
            return False  # Handle invalid IP addresses gracefully
    def design_and_send_packet(self):
        try:
            # Extract values from the GUI
            dst_ip = self.ui.lineEdit_ip_dst.text()
            src_ip = self.ui.lineEdit_ip_source.text()
            protocol = self.ui.comboBox_protocol.currentText()

            # Validate inputs
            if not dst_ip or not src_ip:
                print("Source and destination IPs must be specified.")
                return
            
            # Create the IP layer
            ip_layer = IP(src=src_ip, dst=dst_ip)
            
            # Determine the protocol and construct the packet
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
            elif protocol == "DHCP":
                # DHCP packets typically don't require source and destination IPs
                packet = IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / "DHCP Packet"
                return
            elif protocol == "DNS":
                packet = ip_layer / UDP(dport=53) / DNS(rd=1, qd="example.com")  # Example DNS query
            else:
                print("Unsupported protocol selected.")
                return
            # Send the packet
            send(packet, verbose=False)
        except Exception as e:
            print(f"Error sending packet: {e}")
    def apply_filter(self):
        try:
            """Filter packets based on selected protocols, source/destination IPs, and ComboBox selection."""
            # Map checkbox states to protocol names
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
                "other": self.ui.checkBox_10.isChecked(),
            }
            
            self.ui.tableWidget.setRowCount(0)
            # Check if all protocol filters are unchecked and both src and dst filters are empty
            src_filter = self.ui.lineEdit_2.text().strip()
            dst_filter = self.ui.lineEdit_5.text().strip()
            port_filter=self.ui.lineEdit.text().strip()
            stime = self.ui.dateTimeEdit.dateTime().toSecsSinceEpoch()
            etime = self.ui.dateTimeEdit_2.dateTime().toSecsSinceEpoch()

                # Check if all protocol filters are unchecked and both src and dst filters are empty
            if not any(protocol_filters.values()) and not src_filter and not dst_filter and not port_filter and stime == 946677600 and etime == 946677600:
                    print("No protocols selected, and both source and destination filters are empty.")
                    self.ui.tableWidget.setRowCount(0)
                    self.helperboi()
                    self.filterapplied=False
                    
                    return  # Or handle this case appropriately
                #
            self.filterapplied = True

            # Determine which protocols to filter
            selected_protocols = [protocol for protocol, checked in protocol_filters.items() if checked]
            # Get the source and destination IP filters
            src_filter = self.ui.lineEdit_2.text().strip()
            dst_filter = self.ui.lineEdit_5.text().strip()
            port_filter=self.ui.lineEdit.text().strip()
            # Get ComboBox selection
            combo_selection = self.ui.comboBox.currentText()  # 'Inside' or 'Outside'
            # Clear the table before adding filtered packets
            self.ui.tableWidget.setRowCount(0)

            # Filter packets
            self.filtered_packets = []
            if(self.sensor_obj.senFlag == -1):
                x = self.packets
            else:
                x = self.sensor_obj.sensor_packet
            
            for packet in x:
                src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                protocol = self.get_protocol(packet)

                # Determine if source/destination IPs are local
                src_is_local = self.is_local_ip(src_ip)
                dst_is_local = self.is_local_ip(dst_ip)

                # Check if the packet matches the selected protocols
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
                

                # Check source and destination filters
                packet_time = datetime.fromtimestamp(float(packet.time))
                stime_match = True if stime == 946677600 or stime <= packet.time else False
                etime_match = True if etime == 946677600 or etime >= packet.time else False
                

                src_match = src_filter in src_ip if src_filter else True
                dst_match = dst_filter in dst_ip if dst_filter else True

                # Check ComboBox selection
                if combo_selection == "Inside":
                    ip_match = src_is_local and dst_is_local
                elif combo_selection == "Outside":
                    ip_match = not src_is_local or not dst_is_local
                else:
                    ip_match = True  # Default: no filter based on inside/outside
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
                
                # Include packet if it matches all criteria
                if protocol_match and src_match and dst_match and ip_match and port_match:

                    self.filtered_packets.append(packet)
                    macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                    macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                    # Extract packet length
                    packet_length = int(len(packet))

                # Extract IP version
                    ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                    layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                    # Extract port information for TCP/UDP
                    
                    
                    row_position = self.ui.tableWidget.rowCount()
                    
                    self.ui.tableWidget.insertRow(row_position)
                    self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")))
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
            #self.apply_filter=False
        except Exception as e:
            print(f"Error processing packet: {e}")    
    #end of filter
    def helperboi(self):
                try:
                    
                    x = self.packets
                    for packet in x:
                        src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                        dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                        protocol = self.get_protocol(packet)
                        # Check if the packet matches the selected protocols
                        layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                        # Check source and destination filters
                        packet_time = datetime.fromtimestamp(float(packet.time))
                        macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                        macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                        # Extract packet length
                        packet_length = int(len(packet))

                    # Extract IP version
                        ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                        layer = "udp" if packet.haslayer("UDP") else "tcp" if packet.haslayer("TCP") else "Other"
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
                    print("fr")
    def packet_to_dataframe(self, packet, columns):
        try:
        
            data = {col: '<unknown>' for col in columns}  # Initialize all columns with 'unknown'
            #print(columns)
            #data = pd.DataFrame
            # Map values from packet to DataFrame
            #print(packet)
            if Raw in packet:
                data['frame.len'] = packet.len
                #data['frame.time_epoch'] = packet.time
            if IP in packet:
                data['ip.len'] = packet[IP].len
                data['ip.ttl'] = packet[IP].ttl
                data['ip.proto'] = packet[IP].proto
                data['ip.version'] = packet[IP].version
            if TCP in packet:
                data['tcp.srcport'] = packet[TCP].sport
                data['tcp.dstport'] = packet[TCP].dport
                data['tcp.len'] = len(packet[TCP].payload)
                data['tcp.seq'] = packet[TCP].seq
                data['tcp.flags.ack'] = 1 if packet[TCP].flags.A else 0
                data['tcp.flags.fin'] = 1 if packet[TCP].flags.F else 0
                data['tcp.flags.reset'] = 1 if packet[TCP].flags.R else 0
                data['tcp.window_size'] = packet[TCP].window
                #data['tcp.stream'] = packet[TCP].options if packet[TCP].options else '<unknown>'
            if UDP in packet:
                data['udp.srcport'] = packet[UDP].sport
                data['udp.dstport'] = packet[UDP].dport
                data['udp.length'] = packet[UDP].len
            if DNS in packet:  # Use DNS class directly, not a string
                if packet[DNS].qd:  # Access the DNS layer directly
                    data['dns.qry.type'] = packet[DNS].qd.qtype
                data['dns.flags.response'] = 1 if packet[DNS].qr else 0
                data['dns.flags.recdesired'] = 1 if packet[DNS].rd else 0
            
            #print(data)

            # Return as a DataFrame
            return pd.DataFrame([data])
        except Exception as e:
            print(f"Error processing packet to dataframe function: {e}")
    
    def encodePacket(self, data):
        try:
            for col in data.select_dtypes(include=['object']).columns:
                #unique_count = data[col].nunique()
                #print(f"Processing column: {col} | Unique values: {unique_count} im in encodePacket")

                # For high-cardinality columns, use Label Encoding
                #print(data[col])
                data[col] = self.le.transform(data[col].astype(str))
            
            return data
        except Exception as e:
            print(f"Error encodePacket function: {e}")
    
    def encode(self, data):
        try:
            # Programmatically identify all checksum columns and set up irrelevant columns for dropping
            drop_columns = ['frame.time_epoch', 'tcp.stream']

            # Fill missing values with placeholders
            data = data.fillna('<unknown>')

            # Drop irrelevant columns
            data = data.drop(columns=[col for col in drop_columns if col in data.columns], axis=1)

            # Split into features (X) and target (y)
            X = data.drop(columns=['alert'], axis=1, errors='ignore')
            y = data['alert']

            # Split into training and testing sets
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            # Fit and encode the train data
            for col in X_train.select_dtypes(include=['object']).columns:
                #unique_count = data[col].nunique()
                #print(f"Processing column: {col} | Unique values: {unique_count} im in encode")

                # For high-cardinality columns, use Label Encoding
                X_train[col] = self.le.fit_transform(X_train[col].astype(str))
                #print(self.le.classes_)
            y_train = self.le.fit_transform(y_train.astype(str))
            #print(self.le.classes_)

            #map unknown data
            for col in X_test.select_dtypes(include=['object']).columns:
                X_test[col] = X_test[col].map(lambda s: '<unknown>' if s not in self.le.classes_ else s)
            y_test = y_test.map(lambda s: '<unknown>' if s not in self.le.classes_ else s)
            
            self.le.classes_ = np.append(self.le.classes_, '<unknown>')
            #labelHeaders = list(self.le.classes_)
            #print(labelHeaders)

            #encode test data according to fitted label encoder
            for col in X_test.select_dtypes(include=['object']).columns:
                #unique_count = data[col].nunique()
                #print(f"Processing column: {col} | Unique values: {unique_count}")
                X_test[col] = self.le.transform(X_test[col].astype(str))
            print(y_test)
            y_test = self.le.transform(y_test.astype(str))


            return X_train, y_train, X_test, y_test
        except Exception as e:
            print(f"Error encode function: {e}")
    
class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(object)
    readPackets = []

    def run(self):
        try:
            global packetInput, packetFile, packetIndex
            
            print(packetInput)
            print("GOOGOO")
            window.packets.clear()
            window.tableWidget.setRowCount(0)
            match packetInput:
                case 0:
                    sniff(prn=self.emit_packet, store=False, stop_filter=lambda _: packetInput != 0)
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

        global packetInput, clearRead
        #line edit related bug fix
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
       # Initialize PacketSystem and SensorSystem without passing each other directly
        self.PacketSystemobj = PacketSystem(self)
        self.SensorSystemobj = SensorSystem(self)
        self.Appsystemobj = ApplicationsSystem(self)
        # Now link them after both are created
        self.SensorSystemobj.set_packet_system(self.PacketSystemobj)
        self.PacketSystemobj.set_sensor_system(self.SensorSystemobj)
        self.Appsystemobj.set_packet_system(self.PacketSystemobj)
        #
        self.PacketSystemobj.draw_gauge()
        #Logo Image
        pixmap = QPixmap(r"logo.jpg")
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
        self.tableWidget_4.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Protocol"])
        self.tableWidget_4.cellClicked.connect(self.Appsystemobj.analyze_app)
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
        # Connect checkboxes to the apply_filter method
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
        self.dateTimeEdit.setDisplayFormat("dd-MMM-yyyy hh:mm AP")  # Ensures full year
        self.dateTimeEdit_2.setDisplayFormat("dd-MMM-yyyy hh:mm AP")  # Ensures full year
        self.sniffer_thread = PacketSnifferThread()
        self.sniffer_thread.packet_captured.connect(self.PacketSystemobj.put_packet_in_queue)
        self.sniffer_thread.start()
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.tick)

        self.num=100
      
        self.stats_timer.start(100 )
        self.packet_per_seconds_timer = QTimer()
        self.packet_per_seconds_timer.timeout.connect(self.ppsttick)
        self.packet_per_seconds_timer.start(1000)
        self.ct = 0
        self.pushButton_2.clicked.connect(self.open_analysis)
        self.pushButton_3.clicked.connect(self.open_tool)
        self.lineEdit.setStyleSheet("""
            QLineEdit {
                background-color: grey
            }
        """)
        self.lineEdit_2.setStyleSheet("""
            QLineEdit {
                background-color: grey
            }
        """)
        self.lineEdit_3.setStyleSheet("""
            QLineEdit {
                background-color: grey
            }
        """)
        self.lineEdit_4.setStyleSheet("""
            QLineEdit {
                background-color: grey
            }
        """)
        self.lineEdit_5.setStyleSheet("""
            QLineEdit {
                background-color: grey
            }
        """)
    def open_tool(self):
        try:
            self.secondary_widget2 = Window_Tools(self)
            self.hide()
            self.secondary_widget2.show()
        except Exception as e:
            print(f"Error in open_tool function: {e}")
    def open_analysis(self):
            try:

                self.secondary_widget = Window_Analysis(self)  # Pass reference to the main window
                self.hide()
                self.secondary_widget.show()
            except Exception as e:
                print(f"Error in open_analysis function: {e}")
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
                        # Check if the packet matches the selected protocols
                        layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                        # Check source and destination filters
                        packet_time = datetime.fromtimestamp(float(packet.time))
                        macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                        macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                        # Extract packet length
                        packet_length = int(len(packet))

                    # Extract IP version
                        ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                        layer = (
    "udp" if packet.haslayer("UDP") 
    else "tcp" if packet.haslayer("TCP") 
    else "icmp" if packet.haslayer("ICMP") 
    else "N/A"
)
                        # Extract port information for TCP/UDP
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
                        # Add MAC addresses and port info to the table
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
                    self.PacketSystemobj.tot_icmp_packets=0
                    self.PacketSystemobj.tot_tcp_packets=0
                    self.PacketSystemobj.tot_udp_packets=0
                    self.PacketSystemobj.packets.clear()
                    self.PacketSystemobj.qued_packets.clear()
                    packetInput = 1
                    
                    
                elif ext == '.csv':
                    packetInput = 2
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
            packetFile = ""
            self.sniffer_thread.quit()  # Stops the current thread
            self.sniffer_thread.wait()  # Wait for the thread to finish
            self.sniffer_thread.start()  # Start a new thread
        except Exception as e:
            print(f"Error in resetInput function: {e}")
 
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Naswail()
    window.show()
    sys.exit(app.exec())
