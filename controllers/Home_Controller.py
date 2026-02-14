import numpy as np
import os
import platform
import subprocess
import ipaddress
import matplotlib.pyplot as plt
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from scapy.all import *
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from datetime import datetime
from collections import defaultdict
import traceback
import threading
from plugins.home.PacketSniffer import PacketSnifferThread
from plugins.home.PacketFabricator import BasicPacketFabricator

#sudo /home/hamada/Downloads/Naswail-SIEM-Tool-main/.venv/bin/python /home/hamada/Downloads/Naswail-SIEM-Tool-main/Code_Main.py


class HomeController:
    def __init__(
        self,
        ui,
        packet_decoder,
        packet_details,
        protocol_extractor,
        error_checker,
        packet_statistics,
        anomaly_detector,
        anomaly_detector_2,
        packet_filter,
        corrupted_packet_list,
        network_log,
        anomalies,
        blacklist,
        blocked_ports,
        list_of_activity,
        qued_packets,
        packets,
        time_series,
        sen_info,
        sensor_system,
        application_system,
        packet_exporter,
        scene,
        totINpacekts,
        totOUTpacekts,
        packetStats,
        bandwidthData,
    ):
        #======================================================================================
        #======================================================================================
        #                                   Variables Handling
        #======================================================================================
        #======================================================================================
        self.ui = ui
        self.scene = scene
        
        # Packet Variables
        self.packetInput = 0
        self.filterapplied=False
        self.typeOFchartToPlot=0 # 0:gauge chart, 1: donut chart
        self.packets = []
        self.times = []
        self.counts = []
        self.capture = -1
        self.start_time = QTime.currentTime()
        self.elapsed_seconds = 0
        self.elapsedTime = 0
        self.packetDecoder = packet_decoder
        self.packetDetails = packet_details
        self.protocolExtractor = protocol_extractor
        self.error_checker = error_checker
        self.packetStatistics = packet_statistics
        self.anomalyDetector = anomaly_detector
        self.anomalyDetector_2 = anomaly_detector_2
        self.packetFilter = packet_filter
        self.corrupted_packet = corrupted_packet_list
        self.networkLog = network_log
        self.anomalies = anomalies
        self.blacklist = blacklist
        self.blocked_ports = blocked_ports
        self.list_of_activity = list_of_activity
        self.qued_packets = qued_packets
        self.packets = packets
        self.time_series = time_series
        self.packetExporter = packet_exporter
        self.process_packet_index=0
        self.bandwidth_data = bandwidthData
        self.captured_packets = []
        self.pcap_packets = []
        self.que_flag=False
        self.pcap_process_packet_index = 0
        self.filtered_packets = []
        self.packet_features = []
        self.new_packet_features = []
        self.total_inside_packets = totINpacekts
        self.total_outside_packets = totOUTpacekts
        self.inside_packets = 0
        self.outside_packets = 0
        self.inside_percentage = 0
        self.filterapplied = False
        self.application_filter_flag=False
        self.packet_stats = packetStats
        self.unique_anomalies = set()  # Track unique (src_ip, dst_ip, attack_name) tuples
        self.capture = -1
        self.tot_tcp_packets = 0
        self.tot_udp_packets = 0
        self.tot_icmp_packets = 0
        self.rate_of_packets=0
        self.recently_qued_packets=0
        self.typeOFchartToPlot=0
        self.flag_process_packet=False
        self.packetfile = 1
        self.local_packets = []
        self.processpacket()
        self.alert_timer_started = False
        self.snort_alerts = defaultdict(list)
        
        # Sensor Variables
        self.sen_info = sen_info
        self.sensorSystem = sensor_system
        self.sensor_packet = []
        self.sensors_name = []
        self.senFlag = -1 # indicate filtering by sensors
        self.singleSenFlag = -1 # indicate filtering by single sensor
        self.sen_ct = 0
        self.ct_sensor_packet=[] # used in analyis to know the number packets in realtion to each sensor    
        self.sensors = {}
        self.draw_gauge()

        # Apps Variables
        self.apps = dict()
        self.applicationSystem = application_system

        #======================================================================================
        #======================================================================================
        #                                   UI Handling
        #======================================================================================
        #======================================================================================
        pixmap = QPixmap("resources/logo.png")
        self.pixmap_item = QGraphicsPixmapItem(pixmap)
        self.scene.addItem(self.pixmap_item)
        self.ui.graphicsView.setScene(self.scene)
        self.ui.graphicsView.setFixedSize(71, 61)
        self.ui.graphicsView.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        
        self.ui.tableWidget.setColumnCount(10)
        self.ui.tableWidget.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Protocol","layer","macsrc","macdst","srcport","dstport","length","IP version"])
        self.ui.tableWidget.cellClicked.connect(self.handle_details_click)
        self.ui.tableWidget.cellClicked.connect(self.handle_decode_click)
        self.ui.tabWidget.currentChanged.connect(lambda index: self.change_chart(1) if index == 2 else self.change_chart(0))
        self.ui.tabWidget.currentChanged.connect(lambda index: self.get_applications_with_ports() if index == 3 else None)
        self.ui.tabWidget.currentChanged.connect(lambda index: self.packet_statistics() if index == 5 else None)
        self.ui.tabWidget.currentChanged.connect(lambda index: self.display_log() if index == 7 else None)
        self.ui.tableWidget_2.setColumnCount(2)
        self.ui.tableWidget_2.setHorizontalHeaderLabels(["Name", "IP"])
        self.ui.tableWidget_2.cellClicked.connect(self.filter_sensors)
        self.ui.tableWidget_3.setColumnCount(5)
        self.ui.tableWidget_3.setHorizontalHeaderLabels(["Port", "Application", "IP","CPU","Memory-percent"])
        self.ui.tableWidget_3.cellClicked.connect(self.analyze_app)
        self.ui.tableWidget_4.setColumnCount(4)
        self.ui.tableWidget_4.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Attack Type"])
        #self.ui.tableWidget_4.cellClicked.connect(self.analyze_app)
        self.ui.pushButton_5.clicked.connect(self.toggleCapture)
        self.ui.pushButton_6.clicked.connect(self.toggleCapture)
        self.ui.pushButton_7.clicked.connect(self.toggleSenFlag)
        self.ui.actionImport_Packets.triggered.connect(self.import_file)
        self.ui.actionExport_Packets.triggered.connect(self.handle_export_packets)
        self.ui.actionLive_Capture.triggered.connect(self.resetInput)
        self.ui.buttonBox_2.clicked.connect(self.handle_sensor_button)
        self.ui.pushButton_10.clicked.connect(lambda _: self.updateBlacklist(1))
        self.ui.pushButton_11.clicked.connect(lambda _: self.updateBlacklist(2))
        self.ui.pushButton_12.clicked.connect(lambda _:self.save_log_to_file())
        self.ui.pushButton_apply.clicked.connect(self.fabricate_packet)
        self.ui.pushButton.clicked.connect(self.resetfilter)
       
        self.ui.checkBox.stateChanged.connect(self.apply_filter)      # UDP
        self.ui.checkBox_2.stateChanged.connect(self.apply_filter)    # TCP
        self.ui.checkBox_3.stateChanged.connect(self.apply_filter)    # ICMP
        self.ui.checkBox_4.stateChanged.connect(self.apply_filter)    # DNS
        self.ui.checkBox_5.stateChanged.connect(self.apply_filter)    # DHCP
        self.ui.checkBox_6.stateChanged.connect(self.apply_filter)    # HTTP
        self.ui.checkBox_7.stateChanged.connect(self.apply_filter)    # HTTPS
        self.ui.checkBox_8.stateChanged.connect(self.apply_filter)    # TELNET
        self.ui.checkBox_9.stateChanged.connect(self.apply_filter)    # FTP
        self.ui.checkBox_10.stateChanged.connect(self.apply_filter)   # Other
        self.ui.pushButton_9.clicked.connect(self.apply_filter)
        self.ui.dateTimeEdit.setDisplayFormat("dd-MMM-yyyy hh:mm AP")  
        self.ui.dateTimeEdit_2.setDisplayFormat("dd-MMM-yyyy hh:mm AP")  
        self.sniffer_thread = PacketSnifferThread()
        self.sniffer_thread.packet_captured.connect(self.put_packet_in_queue)
        self.sniffer_thread.set_source('live', '_')
        self.sniffer_thread.start()
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.tick)
        self.stats_timer.start(500)
        self.packet_per_seconds_timer = QTimer()
        self.packet_per_seconds_timer.timeout.connect(self.ppsttick)
        self.packet_per_seconds_timer.start(1000)
        # self.IDS_timer = QTimer()
        # self.IDS_timer.timeout.connect(self.IDStick)
        # self.IDS_timer.start(30000)
        self.ct = 0
        #notifications

    #======================================================================================
    #======================================================================================
    #                              Packet System Handling
    #======================================================================================
    #======================================================================================
    def get_row_color(self, packet):
        """Determine background color based on packet characteristics"""
        try:
            # Check if packet is in anomalies (priority 1)
            if packet in self.anomalies:
                return "rgba(255, 140, 140, 150)"  # Light red for anomalies
                
            # Check if packet is from a blacklisted IP (priority 2)
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                if src_ip in self.blacklist or dst_ip in self.blacklist:
                    return "rgba(200, 100, 100, 150)"  # Darker red for blacklisted IPs
            
            # Check if packet is corrupted (priority 3)
            if packet in self.corrupted_packet:
                return "rgba(255, 200, 100, 150)"  # Orange for corrupted packets
                
            # Check protocol type (priority 4)
            protocol = self.protocolExtractor.extract_protocol(packet)
            if protocol == "http":
                return "rgba(144, 238, 144, 150)"  # Light green for HTTP
            elif protocol == "https":
                return "rgba(144, 238, 144, 150)"  # Light green for HTTPS
            elif protocol == "dns":
                return "rgba(202, 255, 191, 150)"  # Light green for DNS
            elif protocol == "icmp":
                return "rgba(255, 245, 186, 150)"  # Light yellow for ICMP
            
            # Check transport layer (priority 5)
            if packet.haslayer("TCP"):
                return "rgba(151, 203, 255, 150)"  # Light blue for TCP
            elif packet.haslayer("UDP"):
                return "rgba(255, 182, 193, 150)"  # Light pink for UDP
                    
            # Default color (no special characteristics)
            return "transparent"  # Default transparent background
            
        except Exception as e:
            print(f"Error in get_row_color: {e}")
            return "transparent"  # Return transparent on error instead of None

    def get_qcolor(self, rgba_str):
        """Convert an rgba string to a QColor object"""
        try:
            if rgba_str == "transparent":
                return QColor(0, 0, 0, 0)
                
            # Parse the rgba string
            rgba_parts = rgba_str.replace("rgba(", "").replace(")", "").split(",")
            r = int(rgba_parts[0].strip())
            g = int(rgba_parts[1].strip())
            b = int(rgba_parts[2].strip())
            a = int(rgba_parts[3].strip())
            
            return QColor(r, g, b, a)
        except Exception as e:
            print(f"Error creating QColor from {rgba_str}: {e}")
            return QColor(0, 0, 0, 0)  # Default transparent on error

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
            if self.senFlag == 1 or self.singleSenFlag == 1:
                self.typeOFchartToPlot=1
                
            if self.typeOFchartToPlot == 1:
                self.ui.graphicsView_2.setScene(None)
                self.show_donut_chart()
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
            
            # We'll add the counter text below the gauge in a separate text element
            # This empty text in the center helps maintain layout
            ax.text(0, 0.5, "", horizontalalignment='center', verticalalignment='center')

            # add numbers to the gauge
            for value in range(0, 1100, 100):
                theta = start_angle + (value / max_value) * (end_angle - start_angle)
                ax.text(theta, 1.1, str(value), horizontalalignment='center', verticalalignment='center', fontsize=8, color='white')

            # set the limits for the polar plot to the top half only
            ax.set_ylim(0, 1)
            ax.set_xlim(start_angle, end_angle)

            ax.grid(False)
            ax.set_yticks([])
            ax.set_xticks([])

            # Remove polar labels
            ax.set_theta_zero_location('N')
            ax.set_theta_direction(-1)

            # Add digital-style display box for packets per second
            counter_text = f"{int(current_value)}"
            
            # Add "packets/sec" label above the rectangle - moved higher
            fig.text(0.5, 0.88, "packets/sec", fontsize=10, color='white',
                   horizontalalignment='center', verticalalignment='center')
            
            # Create a rectangle for the digital display - adjusted size and position
            rect = plt.Rectangle((0.32, 0.72), 0.36, 0.12, transform=fig.transFigure, 
                               facecolor='#2D2A2E', edgecolor='#40E0D0', linewidth=2)
            fig.patches.append(rect)
            
            # Add the counter text with digital font style - moved higher
            fig.text(0.5, 0.78, counter_text, fontsize=24, fontweight='bold', color='#40E0D0',
                   horizontalalignment='center', verticalalignment='center', family='monospace')
            
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
            
    def put_packet_in_queue(self, packets):
        try:
            # packets is now a list
            if self.packetInput in (0, 1):
                self.qued_packets.extend(packets)  # <-- extend instead of append
                self.recently_qued_packets += len(packets)

                if self.packetInput == 1:
                    self.que_flag = False

        except Exception as e:
            print(f"Error putting packet in queue: {e}")
    def updateBlacklist(self, f):
        try:
            ip = self.ui.lineEdit_6.text().strip()
            if(f == 1):
                self.blacklist.append(ip)
                self.block_ip(ip)
                self.networkLog.append("Blocked IP: " + ip)
                
            else:
                self.blacklist.remove(ip)
                self.unblock_ip(ip)
                self.networkLog.append("Unblocked IP: " + ip)
               

            model = QStringListModel()
            model.setStringList(self.blacklist)
            self.ui.listView_4.setModel(model)
        except Exception as e:
            print(f"Error updating blacklist: {e}")
    
    def packet_statistics(self):
        try:
            stats_text = self.packetStatistics.analyze(
                packets=self.packets,
                totals={
                    "tcp": self.tot_tcp_packets,
                    "udp": self.tot_udp_packets,
                    "icmp": self.tot_icmp_packets,
                },
                app_proto_counts=self.packet_stats
            )

            model = QStringListModel()
            model.setStringList(stats_text)
            self.ui.listView_3.setModel(model)

        except Exception as e:
            print(f"Error in packet_statistics function: {e}")

    def change_chart(self,index):#function for changing between guage and donut chart
        if index==1:
            self.typeOFchartToPlot=1
            self.show_donut_chart()
        else:
            self.typeOFchartToPlot=0

    def processpacket(self):
        try:
            thread = threading.Thread(target=self.process_packet)
            thread.start()
        except Exception as e:
            print(f"Error in process_packet function: {e}")
    
    def process_packet(self):
        try:
            if self.flag_process_packet==False:
                self.flag_process_packet=True
                if self.packetInput == 0:
                    packet = self.qued_packets[self.process_packet_index] 
                if self.packetInput == 1:
                    packet = self.qued_packets[self.pcap_process_packet_index]
                    
                # Extract packet information once
                packet_info = {
                    'timestamp': float(packet.time),
                    'src_ip': packet["IP"].src if packet.haslayer("IP") else "N/A",
                    'dst_ip': packet["IP"].dst if packet.haslayer("IP") else "N/A",
                    'has_tcp': packet.haslayer("TCP"),
                    'has_udp': packet.haslayer("UDP"),
                    'has_icmp': packet.haslayer("ICMP"),
                    'macsrc': packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A",
                    'macdst': packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A",
                    'length': int(len(packet)),
                    'ip_version': "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                }
                
                # Extract ports if available
                if packet_info['has_tcp']:
                    packet_info['sport'] = packet["TCP"].sport
                    packet_info['dport'] = packet["TCP"].dport
                    self.packet_stats["tcp"] += 1
                    self.tot_tcp_packets += 1
                elif packet_info['has_udp']:
                    packet_info['sport'] = packet["UDP"].sport
                    packet_info['dport'] = packet["UDP"].dport
                    self.packet_stats["udp"] += 1
                    self.tot_udp_packets += 1
                elif packet_info['has_icmp']:
                    self.packet_stats["icmp"] += 1
                    packet_info['sport'] = None
                    packet_info['dport'] = None
                else:
                    packet_info['sport'] = None
                    packet_info['dport'] = None

                # Check for blacklisted IPs
                if (packet_info['src_ip'] in self.blacklist or 
                    packet_info['dst_ip'] in self.blacklist or 
                    packet_info['dport'] in self.blocked_ports):
                    row_position = self.ui.tableWidget.rowCount()
                    self.ui.tableWidget.insertRow(row_position)
                    for col in range(11):
                        item = QTableWidgetItem("Blocked")
                        item.setBackground(QColor(180, 0, 0, 100))
                        item.setForeground(QColor(255, 255, 255))
                        self.ui.tableWidget.setItem(row_position, col, item)
                else:
                    self.packets.append(packet)
                    
                    # Handle packet storage limits
                    # if len(self.packets) >= 15000:
                    #     removed_elements = self.packets[0:5000]
                    #     del self.qued_packets[0:5000]
                    #     del self.packets[0:5000]
                    #     self.process_packet_index -= 5000
                    #     for key in list(self.time_series.keys())[:2000]:
                    #         del self.time_series[key]
                    #     wrpcap("data/packet_file" + str(self.packetfile) + ".pcap", removed_elements)
                    #     removed_elements.clear()
                    #     self.packetfile += 1

                    # Verify checksum and update stats
                    is_corrupted = self.error_checker.is_corrupted(packet)
                    protocol = self.protocolExtractor.extract_protocol(packet)
                    packet_info['protocol'] = protocol
                    packet_info['layer'] = (
                        "udp" if packet_info['has_udp']
                        else "tcp" if packet_info['has_tcp']
                        else "icmp" if packet_info['has_icmp']
                        else "N/A"
                    )

                    # Update packet stats
                    self.packet_stats["total"] += 1
                    if protocol in self.packet_stats:
                        self.packet_stats[protocol] += 1
                    else:
                        self.packet_stats["other"] += 1

                    # Check for local traffic
                    if self.is_local_ip(packet_info['src_ip']):
                        self.total_inside_packets += 1
                        self.local_packets.append(packet)
                    else:
                        self.total_outside_packets += 1

                    # Only update UI if not filtering
                    if not (self.filterapplied or 
                        self.senFlag == 1 or 
                        self.singleSenFlag == 1 or 
                        self.application_filter_flag):
                        
                        if self.capture == 1:
                            self.ui.label_6.setStyleSheet("background-color: Red;")
                            self.captured_packets.append(packet)
                        else:
                            self.ui.label_6.setStyleSheet("QLabel { color: white; }")
                        
                        self.new_packet_features.append([packet_info['length'], packet_info['timestamp'], protocol])
                        
                        # Check for anomalies
                        # if not self.alert_timer_started:
                        #     self.alert_timer_started = True
                        #     threading.Timer(15.0, lambda: self.snort_alerts[(packet_info['src_ip'], packet_info['dst_ip'])].append("Port Scanning")).start()
                        
                        attack_label = self.anomalyDetector.check(packet)
                        if attack_label:
                            self.anomalies.append(packet)
                            anomaly_signature = (packet_info['src_ip'], packet_info['dst_ip'], attack_label)
                            
                            if anomaly_signature not in self.unique_anomalies:
                                self.unique_anomalies.add(anomaly_signature)
                                current_time = datetime.now().strftime("%H:%M:%S")
                                self.networkLog.append(f"{current_time} - An anomaly occurred")

                                # Add to anomaly table
                                row_position = self.ui.tableWidget_4.rowCount()
                                self.ui.tableWidget_4.insertRow(row_position)

                                row_color = self.get_row_color(packet)
                                qcolor = self.get_qcolor(row_color)

                                items = [
                                    QTableWidgetItem(datetime.fromtimestamp(packet_info['timestamp']).strftime("%I:%M:%S %p")),
                                    QTableWidgetItem(packet_info['src_ip']),
                                    QTableWidgetItem(packet_info['dst_ip']),
                                    QTableWidgetItem(str(attack_label))
                                ]

                                for item in items:
                                    item.setBackground(qcolor)
                                for col, item in enumerate(items):
                                    self.ui.tableWidget_4.setItem(row_position, col, item)

                        
                        # Add to main table
                        row_position = self.ui.tableWidget.rowCount()
                        self.ui.tableWidget.insertRow(row_position)
                        
                        # Get row color
                        row_color = self.get_row_color(packet)
                        qcolor = self.get_qcolor(row_color)
                        
                        # Create items with background color
                        items = [
                            QTableWidgetItem(datetime.fromtimestamp(packet_info['timestamp']).strftime("%I:%M:%S %p")),
                            QTableWidgetItem(packet_info['src_ip']),
                            QTableWidgetItem(packet_info['dst_ip']),
                            QTableWidgetItem(protocol),
                            QTableWidgetItem(packet_info['layer']),
                            QTableWidgetItem(packet_info['macsrc']),
                            QTableWidgetItem(packet_info['macdst']),
                            QTableWidgetItem(str(packet_info['sport']) if packet_info['sport'] else "N/A"),
                            QTableWidgetItem(str(packet_info['dport']) if packet_info['dport'] else "N/A"),
                            QTableWidgetItem(str(packet_info['length'])),
                            QTableWidgetItem(packet_info['ip_version'])
                        ]
                        
                        # Apply background color to each item
                        if row_color != "transparent":
                            for item in items:
                                item.setBackground(qcolor)
                                if "100, 100" in row_color or "100, 170" in row_color:
                                    item.setForeground(QColor(255, 255, 255))
                        
                        # Set items in the table
                        for col, item in enumerate(items):
                            self.ui.tableWidget.setItem(row_position, col, item)

                # Update indices
                if self.packetInput == 0 and self.process_packet_index < len(self.qued_packets):
                    self.process_packet_index += 1
                elif self.packetInput == 1 and self.pcap_process_packet_index < len(self.qued_packets):
                    self.pcap_process_packet_index += 1

                # Update time series
                self.time_series[packet_info['timestamp']] = len(self.packets)

                # Update bandwidth data
                readable_time = datetime.fromtimestamp(packet_info['timestamp']).strftime("%I:%M:%S %p")
                if len(self.bandwidth_data) == 0 or self.bandwidth_data[-1][0] != readable_time:
                    self.bandwidth_data.append((readable_time, packet_info['length']))
                else:
                    self.bandwidth_data[-1] = (readable_time, self.bandwidth_data[-1][1] + packet_info['length'])
            self.flag_process_packet = False
        except Exception as e:
            print(f"Error processing packet: {e}")
            tb = traceback.format_exc()
            print("Traceback details:")
            print(tb)

    def display_log(self):
        try:
                model = QStringListModel()
                model.setStringList(self.networkLog)
                self.ui.listView_5.setModel(model)
        except Exception as e:
            print(f"Error displaying log: {e}")
    def save_log_to_file(self):
        try:
            with open("data/network_log.txt", "w", encoding="utf-8") as log_file:
                logText = "\n".join(self.networkLog)
                log_file.write(logText)
            print("Log saved successfully to 'data/network_log.txt'.")
        except Exception as e:
            print(f"Error saving log to file: {e}")

    def is_local_ip(self,ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private  # returns True for local IPs, False for outside
        except ValueError:
    
            return False  # handle invalid IP addresses
        
    def fabricate_packet(self):
        src_ip = self.ui.lineEdit_ip_source.text()
        dst_ip = self.ui.lineEdit_ip_dst.text()
        protocol = self.ui.comboBox_protocol.currentText()

        fabricator = BasicPacketFabricator()
        success = fabricator.fabricate_and_send(src_ip, dst_ip, protocol)

        if success:
            print("Packet sent successfully.")
        else:
            print("Failed to send packet.")

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

            src_filter = self.ui.lineEdit_2.text().strip()
            dst_filter = self.ui.lineEdit_5.text().strip()
            port_filter = self.ui.lineEdit.text().strip()
            stime = self.ui.dateTimeEdit.dateTime().toSecsSinceEpoch()
            etime = self.ui.dateTimeEdit_2.dateTime().toSecsSinceEpoch()
            direction = self.ui.comboBox.currentText()

            # Nothing selected? fallback
            if not any(protocol_filters.values()) and not src_filter and not dst_filter and not port_filter and stime == 946677600 and etime == 946677600:
                self.rebuild_packets()
                self.filterapplied = False
                return

            self.filterapplied = True
            selected_protocols = [proto for proto, checked in protocol_filters.items() if checked]

            # Gather packets
            packet_source = self.sensor_packet if self.senFlag == 1 else self.packets
            criteria = {
                "protocols": selected_protocols,
                "src_ip": src_filter,
                "dst_ip": dst_filter,
                "port": port_filter,
                "start_time": stime,
                "end_time": etime,
                "direction": direction
            }

            self.filtered_packets = self.packetFilter.filter_packets(packet_source, criteria)

            # Clear and refill UI
            self.ui.tableWidget.setRowCount(0)

            # Second pass: update UI with filtered packets
            for packet in self.filtered_packets:
                # Get row color based on packet characteristics
                row_color = self.get_row_color(packet)
                qcolor = self.get_qcolor(row_color)

                # Extract packet information for display
                packet_info = {
                    'timestamp': float(packet.time),
                    'src_ip': packet["IP"].src if packet.haslayer("IP") else "N/A",
                    'dst_ip': packet["IP"].dst if packet.haslayer("IP") else "N/A",
                    'protocol': self.protocolExtractor.extract_protocol(packet),
                    'layer': (
                        "udp" if packet.haslayer("UDP") 
                        else "tcp" if packet.haslayer("TCP") 
                        else "icmp" if packet.haslayer("ICMP") 
                        else "N/A"
                    ),
                    'macsrc': packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A",
                    'macdst': packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A",
                    'length': int(len(packet)),
                    'ip_version': "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                }

                # Extract ports
                if packet.haslayer("TCP"):
                    packet_info['sport'] = packet["TCP"].sport
                    packet_info['dport'] = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    packet_info['sport'] = packet["UDP"].sport
                    packet_info['dport'] = packet["UDP"].dport
                else:
                    packet_info['sport'] = None
                    packet_info['dport'] = None

                # Create table row
                row_position = self.ui.tableWidget.rowCount()
                self.ui.tableWidget.insertRow(row_position)

                # Create items with background color
                readable_time = datetime.fromtimestamp(packet_info['timestamp']).strftime("%I:%M:%S %p")
                items = [
                    QTableWidgetItem(readable_time),
                    QTableWidgetItem(packet_info['src_ip']),
                    QTableWidgetItem(packet_info['dst_ip']),
                    QTableWidgetItem(packet_info['protocol']),
                    QTableWidgetItem(packet_info['layer']),
                    QTableWidgetItem(packet_info['macsrc']),
                    QTableWidgetItem(packet_info['macdst']),
                    QTableWidgetItem(str(packet_info['sport']) if packet_info['sport'] else "N/A"),
                    QTableWidgetItem(str(packet_info['dport']) if packet_info['dport'] else "N/A"),
                    QTableWidgetItem(str(packet_info['length'])),
                    QTableWidgetItem(packet_info['ip_version'])
                ]

                # Apply color to items
                if row_color != "transparent":
                    for item in items:
                        item.setBackground(qcolor)
                        if "100, 100" in row_color or "100, 170" in row_color:
                            item.setForeground(QColor(255, 255, 255))

                # Add items to table
                for col, item in enumerate(items):
                    self.ui.tableWidget.setItem(row_position, col, item)

        except Exception as e:
            print(f"Error in apply_filter: {e}")
            tb = traceback.format_exc()
            print("Traceback details:")
            print(tb)
    
    def handle_details_click(self, row, column):
        try:
            if self.filterapplied:
                packet = self.filtered_packets[row]
            else:
                packet = self.packets[row]

            details_list = self.packetDetails.extract_details(packet)
            model = QStringListModel()
            model.setStringList(details_list)
            self.ui.listView.setModel(model)

        except Exception as e:
            print(f"Error displaying packet details: {e}")

    
    def handle_decode_click(self, row, column):
        try:
            if not self.filterapplied:
                packet = self.packets[row]
                content = self.packetDecoder.decode(packet)
                model = QStringListModel()
                model.setStringList(content)
                self.ui.listView_2.setModel(model)
        except Exception as e:
            print(f"[handle_decode_click] Failed to decode packet: {e}")
    
    def rebuild_packets(self):#for rebuilding the packets
        try: 
            x = self.packets
            for packet in x:
                src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                protocol = self.protocolExtractor.extract_protocol(packet)
                
                layer = (
                    "udp" if packet.haslayer("UDP") 
                    else "tcp" if packet.haslayer("TCP") 
                    else "icmp" if packet.haslayer("ICMP") 
                    else "N/A"
                )
                
                packet_time = datetime.fromtimestamp(float(packet.time))
                readable_time = packet_time.strftime("%I:%M:%S %p")
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
                
                # Get row color
                row_color = self.get_row_color(packet)
                qcolor = self.get_qcolor(row_color)
                
                # Create items with color
                items = [
                    QTableWidgetItem(readable_time),
                    QTableWidgetItem(src_ip),
                    QTableWidgetItem(dst_ip),
                    QTableWidgetItem(protocol),
                    QTableWidgetItem(layer),
                    QTableWidgetItem(macsrc),
                    QTableWidgetItem(macdst),
                    QTableWidgetItem(str(sport) if sport else "N/A"),
                    QTableWidgetItem(str(dport) if dport else "N/A"),
                    QTableWidgetItem(str(packet_length)),
                    QTableWidgetItem(ip_version)
                ]
                
                # Apply color to items
                if row_color != "transparent":
                    for item in items:
                        item.setBackground(qcolor)
                        # For dark backgrounds, use white text for better contrast
                        if "100, 100" in row_color or "100, 170" in row_color:
                            item.setForeground(QColor(255, 255, 255))
                
                # Add items to table
                for col, item in enumerate(items):
                    self.ui.tableWidget.setItem(row_position, col, item)
        except:
            print("fr")

    #======================================================================================
    #======================================================================================
    #                             Sensor System Handling
    #======================================================================================
    #======================================================================================
    def filter_sensors(self, row, col):
        try:
            self.singleSenFlag *= -1
            self.senFlag = -1

            if self.singleSenFlag == 1:
                # 1. Extract selected sensor MAC
                sensor_mac = self.ui.tableWidget_2.item(row, col).text()
                self.ui.tableWidget.setRowCount(0)

                # 2. Prepare criteria for the filter plugin
                criteria = {"mac_addresses": [sensor_mac]}
                filtered = self.packetFilter.filter_packets(self.packets, criteria)

                self.sensor_packet.clear()

                # 3. Display all packets that match
                for packet in filtered:
                    try:
                        src_mac = packet["Ether"].src if packet.haslayer("Ether") else "N/A"
                        dst_mac = packet["Ether"].dst if packet.haslayer("Ether") else "N/A"
                        protocol = self.protocolExtractor.extract_protocol(packet)
                        port = packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
                        ip_src = packet["IP"].src if packet.haslayer("IP") else "N/A"
                        ip_dst = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                        packet_length = int(len(packet))
                        sport = packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
                        dport = packet["TCP"].dport if packet.haslayer("TCP") else "N/A"
                        ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"
                        layer = (
                            "udp" if packet.haslayer("UDP")
                            else "tcp" if packet.haslayer("TCP")
                            else "icmp" if packet.haslayer("ICMP")
                            else "N/A"
                        )

                        self.sensor_packet.append(packet)

                        row_position = self.ui.tableWidget.rowCount()
                        self.ui.tableWidget.insertRow(row_position)

                        row_color = self.get_row_color(packet)
                        qcolor = self.get_qcolor(row_color)

                        readable_time = datetime.fromtimestamp(packet.time).strftime("%I:%M:%S %p")
                        items = [
                            QTableWidgetItem(readable_time),
                            QTableWidgetItem(ip_src),
                            QTableWidgetItem(ip_dst),
                            QTableWidgetItem(protocol),
                            QTableWidgetItem(layer),
                            QTableWidgetItem(src_mac),
                            QTableWidgetItem(dst_mac),
                            QTableWidgetItem(str(sport) if sport else "N/A"),
                            QTableWidgetItem(str(dport) if dport else "N/A"),
                            QTableWidgetItem(str(packet_length)),
                            QTableWidgetItem(ip_version)
                        ]

                        # Apply color to items
                        if row_color != "transparent":
                            for item in items:
                                item.setBackground(qcolor)
                                if "100, 100" in row_color or "100, 170" in row_color:
                                    item.setForeground(QColor(255, 255, 255))

                        for col, item in enumerate(items):
                            self.ui.tableWidget.setItem(row_position, col, item)

                    except Exception as inner_e:
                        print(f"[filter_sensors] Error handling packet: {inner_e}")

        except Exception as e:
            print(f"[filter_sensors] Failed to filter: {e}")

    def updateSensor(self, a):
        try:
            senName = self.ui.lineEdit_3.text().strip()
            senMAC = self.ui.lineEdit_4.text().strip()

            if a == 1:
                self.sen_info.append(senName)
                self.sen_info.append(0)
                self.sensorSystem.add_sensor(senName, senMAC)
            else:
                print(f"[UI] Attempting to remove sensor: {senName}")
                self.sensorSystem.remove_sensor(senName)

            plt.close()
            self.show_donut_chart()
            self.displaySensorTable()
        except Exception as e:
            print(f"Error in updateSensor function: {e}")
    
    def displaySensorTable(self):
        try:
            self.show_donut_chart()
            self.ui.tableWidget_2.setRowCount(0)

            for name, mac in self.sensorSystem.list_sensors().items():
                row_position = self.ui.tableWidget_2.rowCount()
                self.ui.tableWidget_2.insertRow(row_position)
                self.ui.tableWidget_2.setItem(row_position, 0, QTableWidgetItem(str(name)))
                self.ui.tableWidget_2.setItem(row_position, 1, QTableWidgetItem(str(mac)))

        except Exception as e:
            print(f"Error in displaySensorTable function: {e}")
        
    def show_donut_chart(self):
        try:
            if self.typeOFchartToPlot == 0:
                self.ui.graphicsView_2.setScene(None)
                return

            sizes = [1]
            labels = ['']
            sensors_dict = self.sensorSystem.list_sensors()

            s = 0
            for s in range(len(sensors_dict)):
                sizes.append(s)
                labels.append('')

            colors = [
                '#E0F7F5', '#B3ECE6', '#8FE0D8',
                '#40E0D0', '#36C9B0', '#2DB39E',
                '#249C8A', '#1B8676', '#126F62',
                '#0A594E', '#03433A', '#002D26',
                '#001612', '#008080', '#00CED1'
            ]

            fig, ax = plt.subplots(figsize=(6, 6))

            wedges, texts = ax.pie(
                sizes,
                labels=labels,
                startangle=90,
                colors=colors,
                wedgeprops=dict(width=0.3)
            )

            ax.axis('equal')
            ax.set_title('Sensors', color='#40E0D0', fontsize=12, fontweight='bold')

            sensor_count = f"{len(sensors_dict)} registered sensors"
            fig.text(0.5, 0.82, sensor_count, fontsize=11, fontweight='bold', color='white',
                    horizontalalignment='center', verticalalignment='center')

            fig.patch.set_visible(False)
            ax.patch.set_alpha(0)

            canvas = FigureCanvas(fig)
            canvas.setStyleSheet("background: transparent;")
            canvas.setGeometry(0, 0, self.ui.graphicsView_2.width(), self.ui.graphicsView_2.height())

            scene = QGraphicsScene()
            scene.setBackgroundBrush(Qt.GlobalColor.transparent)
            scene.addWidget(canvas)
            self.ui.graphicsView_2.setScene(scene)
            plt.close(fig)
        except Exception as e:
            print(f"error in show donut chart function:{e}")

    
    def toggleSenFlag(self):
        try:
            # Flip the global sensor filtering flag
            self.senFlag *= -1
            self.singleSenFlag = -1

            # If turned ON, perform filtering
            if self.senFlag == 1:
                self.ui.tableWidget.setRowCount(0)

                # 1. Prepare criteria for filtering via plugin
                all_sensor_macs = list(self.sensorSystem.list_sensors().values())
                criteria = {"mac_addresses": all_sensor_macs}
                filtered = self.packetFilter.filter_packets(self.packets, criteria)

                # 2. Clear sensor packet list and update sensor stats
                self.sensor_packet.clear()

                for packet in filtered:
                    try:
                        src_mac = packet["Ether"].src if packet.haslayer("Ether") else "N/A"
                        dst_mac = packet["Ether"].dst if packet.haslayer("Ether") else "N/A"
                        protocol = self.protocolExtractor.extract_protocol(packet)
                        port = packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
                        ip_src = packet["IP"].src if packet.haslayer("IP") else "N/A"
                        ip_dst = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                        packet_length = int(len(packet))
                        ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if packet.haslayer("IP") else "N/A"

                        sport = dport = None
                        timestamp = float(packet.time)
                        readable_time = datetime.fromtimestamp(timestamp).strftime("%I:%M:%S %p")

                        if packet.haslayer("TCP"):
                            sport = packet["TCP"].sport
                            dport = packet["TCP"].dport
                        elif packet.haslayer("UDP"):
                            sport = packet["UDP"].sport
                            dport = packet["UDP"].dport

                        # 3. Match to which sensor(s) this packet belongs
                        for sensor_name, sensor_mac in self.sensorSystem.list_sensors().items():
                            if sensor_mac.lower() in src_mac.lower() or sensor_mac.lower() in dst_mac.lower():
                                self.sensor_packet.append(packet)

                                # Update sen_info count
                                for s in range(0, len(self.sen_info) - 1, 2):
                                    if self.sen_info[s] == sensor_name:
                                        self.sen_info[s + 1] += 1

                                # Add to table
                                row_position = self.ui.tableWidget.rowCount()
                                self.ui.tableWidget.insertRow(row_position)
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

                    except Exception as inner_e:
                        print(f"[toggleSenFlag] Error on a filtered packet: {inner_e}")

                # 4. Push count
                self.ct_sensor_packet.append(self.sen_ct)

        except Exception as e:
            print(f"[toggleSenFlag] Failed to toggle sensor flag: {e}")

    #======================================================================================
    #======================================================================================
    #                                   UI Handling
    #======================================================================================
    #======================================================================================
    def get_applications_with_ports(self):
        try:
            self.apps = self.applicationSystem.get_active_applications()
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
            self.application_filter_flag = True
            target_app = self.apps[row]
            self.ui.tableWidget.setRowCount(0) 

            self.filtered_packets = []
            for packet in self.packets:
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
                protocol = self.protocolExtractor.extract_protocol(packet)
                port = packet["TCP"].sport if packet.haslayer("TCP") else "N/A"
                layer = (
                    "udp" if packet.haslayer("UDP") 
                    else "tcp" if packet.haslayer("TCP") 
                    else "icmp" if packet.haslayer("ICMP") 
                    else "N/A"
                )
                if target_app["IP"] in src_ip.lower() or target_app["IP"] in dst_ip.lower() or str(target_app["Port"]) in str(port):
                    self.filtered_packets.append(packet)

                    row_position = self.ui.tableWidget.rowCount()
                    self.ui.tableWidget.insertRow(row_position)
                    
                    # Get color for the packet row
                    row_color = self.get_row_color(packet)
                    qcolor = self.get_qcolor(row_color)
                    
                    # Create items with background color
                    readable_time = datetime.fromtimestamp(packet.time).strftime("%I:%M:%S %p")
                    items = [
                        QTableWidgetItem(readable_time),
                        QTableWidgetItem(src_ip),
                        QTableWidgetItem(dst_ip),
                        QTableWidgetItem(protocol),
                        QTableWidgetItem(layer),
                        QTableWidgetItem(macsrc),
                        QTableWidgetItem(macdst),
                        QTableWidgetItem(str(sport) if sport else "N/A"),
                        QTableWidgetItem(str(dport) if dport else "N/A"),
                        QTableWidgetItem(str(packet_length)),
                        QTableWidgetItem(ip_version)
                    ]
                    
                    # Apply color to items
                    if row_color != "transparent":
                        for item in items:
                            item.setBackground(qcolor)
                            # For dark backgrounds, use white text
                            if "100, 100" in row_color or "100, 170" in row_color:
                                item.setForeground(QColor(255, 255, 255))
                    
                    # Add items to table
                    for col, item in enumerate(items):
                        self.ui.tableWidget.setItem(row_position, col, item)
        except:
            print("Error in analyze_app function")

    #======================================================================================
    #======================================================================================
    #                                   Misc Handling
    #======================================================================================
    #======================================================================================
    def handle_sensor_button(self, button):
        role = self.ui.buttonBox_2.buttonRole(button)

        if role == QDialogButtonBox.ButtonRole.ApplyRole:
            self.updateSensor(1)
        elif role == QDialogButtonBox.ButtonRole.DestructiveRole:
            self.updateSensor(2)
    
    def handle_export_packets(self):
        try:
            packets = self.captured_packets
            path = "data/captured_packets.pcap"
            success = self.packetExporter.export(packets, path)
            if success:
                print("Packets exported successfully.")
            else:
                print("Packet export failed.")
        except Exception as e:
            print(f"Export failed with error: {e}")
    
    def toggleCapture(self):
        self.capture *= -1
        self.capture*=-1

    def import_file(self):
        try:
            self.packetFile, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files ();;PCAP Files (.pcap);;CSV Files (*.csv)")
            if self.packetFile:
                self.process_packet_index=0
                self.pcap_process_packet_index=0
                self.packet_stats={"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0,"http":0,"https":0,"dns":0,"dhcp":0,"ftp":0,"telnet":0}
                self.tot_icmp_packets=0
                self.tot_tcp_packets=0
                self.tot_udp_packets=0
                self.packets.clear()
                self.qued_packets.clear()
                self.anomalies.clear()
                self.ui.tableWidget_4.setRowCount(0)
                print(f"Selected file: {self.packetFile}")
                ext = os.path.splitext(self.packetFile)[1].lower()
                if ext == '.pcap':
                    self.sniffer_thread.stop()
                    self.sniffer_thread = PacketSnifferThread()
                    self.sniffer_thread.packet_captured.connect(self.put_packet_in_queue)
                    self.sniffer_thread.set_source('pcap', self.packetFile)
                    self.sniffer_thread.start() 
                elif ext == '.csv':
                    self.sniffer_thread.stop()
                    self.sniffer_thread = PacketSnifferThread()
                    self.sniffer_thread.packet_captured.connect(self.put_packet_in_queue)
                    self.sniffer_thread.set_source('csv', self.packetFile)
                    self.sniffer_thread.start()
                else:
                    print("Unsupported file type.")
                self.packets.clear()
                self.ui.tableWidget.setRowCount(0)
            else:
                print("No file selected")
        except Exception as e:
            print(f"Error in import_file function: {e}")

    def resetInput(self):
        try:
            self.process_packet_index=0
            self.pcap_process_packet_index=0
            self.packet_stats={"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0,"http":0,"https":0,"dns":0,"dhcp":0,"ftp":0,"telnet":0}
            self.tot_icmp_packets=0
            self.tot_tcp_packets=0
            self.tot_udp_packets=0
            self.packets.clear()
            self.qued_packets.clear()
            self.anomalies.clear()
            self.ui.tableWidget_4.setRowCount(0)
            self.sniffer_thread.stop()
            self.sniffer_thread = PacketSnifferThread()
            self.sniffer_thread.packet_captured.connect(self.put_packet_in_queue)
            self.sniffer_thread.set_source('live', 'Wi-Fi')  # Change 'Wi-Fi' to your interface if needed
            self.sniffer_thread.start()
        except Exception as e:
            print(f"Error in resetInput function: {e}")

    def resetfilter(self):
        try:
            self.draw_gauge()
            checkboxes = [
                self.ui.checkBox,
                self.ui.checkBox_2,
                self.ui.checkBox_3,
                self.ui.checkBox_4,
                self.ui.checkBox_5,
                self.ui.checkBox_6,
                self.ui.checkBox_7,
                self.ui.checkBox_8,
                self.ui.checkBox_9,
                self.ui.checkBox_10
            ]
            for checkbox in checkboxes:
                checkbox.setCheckState(Qt.CheckState.Unchecked)
            self.ui.tableWidget.setRowCount(0)
            
            # Clear the filter text fields
            self.ui.lineEdit.setText("")
            self.ui.lineEdit_2.setText("")
            self.ui.lineEdit_5.setText("")
            
            # Reset to display all packets with proper colors
            for packet in self.packets:
                src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                protocol = self.protocolExtractor.extract_protocol(packet)
                
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
                
                # Get row color based on packet characteristics
                row_color = self.get_row_color(packet)
                qcolor = self.get_qcolor(row_color)
                
                # Create items with background color
                readable_time = datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")
                items = [
                    QTableWidgetItem(readable_time),
                    QTableWidgetItem(src_ip),
                    QTableWidgetItem(dst_ip),
                    QTableWidgetItem(protocol),
                    QTableWidgetItem(layer),
                    QTableWidgetItem(macsrc),
                    QTableWidgetItem(macdst),
                    QTableWidgetItem(str(sport) if sport else "N/A"),
                    QTableWidgetItem(str(dport) if dport else "N/A"),
                    QTableWidgetItem(str(packet_length)),
                    QTableWidgetItem(ip_version)
                ]
                
                # Apply background color to each item
                if row_color != "transparent":
                    for item in items:
                        item.setBackground(qcolor)
                        # For dark backgrounds, use white text for better contrast
                        if "100, 100" in row_color or "100, 170" in row_color:
                            item.setForeground(QColor(255, 255, 255))
                
                # Set items in the table
                for col, item in enumerate(items):
                    self.ui.tableWidget.setItem(row_position, col, item)
            
            self.filterapplied=False
            self.typeOFchartToPlot=0
            self.application_filter_flag=False
            self.senFlag = -1 
            self.singleSenFlag = -1
        except Exception as e:
            print(f"Error in resetfilter function: {e}")
            tb = traceback.format_exc()
            print(tb)
    def ppsttick(self):
        try:
            self.rate_of_packets=self.recently_qued_packets/self.elapsed_seconds
            if self.rate_of_packets>=100 and  self.rate_of_packets<=300:
                current_time = datetime.now().strftime("%H:%M:%S")
                self.networkLog.append(current_time + " - " + "Moderately high increase in packets")
            if self.rate_of_packets>=300 and  self.rate_of_packets<=700:
                current_time = datetime.now().strftime("%H:%M:%S")
                self.networkLog.append(current_time + " - " + "High increase in packets")
            if self.rate_of_packets>=700:
                current_time = datetime.now().strftime("%H:%M:%S")
                self.networkLog.append(current_time + " - " + "Extremely high increase in packets")
            self.recently_qued_packets=0
            self.draw_gauge()
        except Exception as e:
            print(f"Error in ppsttick function: {e}")
    def tick(self):
        try:
            current_time = QTime.currentTime()
            self.elapsed_seconds = self.start_time.secsTo(current_time)
            hours = self.elapsed_seconds // 3600
            minutes = (self.elapsed_seconds % 3600) // 60
            seconds = self.elapsed_seconds % 60
            self.elapsedTime = f"{hours:02}:{minutes:02}:{seconds:02}"
            self.ui.label_6.setText(str(self.elapsedTime))
            if self.process_packet_index < len(self.qued_packets) and self.pcap_process_packet_index < len(self.qued_packets):
                self.process_packet()
                self.packet_statistics()
        except Exception as e:
            print(f"Error in tick function: {e}")

    def IDStick(self):
        try:
            pcap_path = "D:\\Work\\University\\GradProject\\Naswail-SIEM-Tool\\data\\anomalyTest.pcap"
            wrpcap(pcap_path, self.packets)
            anomalies = self.anomalyDetector_2.check(pcap_path)
            for a in anomalies:
                src_ip = a.get('src_ip')
                dst_ip = a.get('dst_ip')
                src_port = a.get('src_port', None)
                dst_port = a.get('dst_port', None)
                protocol = a.get('protocol', None)

                # Find only the *first* matching packet
                for pkt in self.packets:
                    if "IP" not in pkt:
                        continue

                    pkt_src = pkt["IP"].src
                    pkt_dst = pkt["IP"].dst
                    pkt_sport = getattr(pkt, "sport", None)
                    pkt_dport = getattr(pkt, "dport", None)
                    pkt_proto = pkt.lastlayer().name.upper()

                    if (pkt_src == src_ip and
                        pkt_dst == dst_ip and
                        pkt_sport == src_port and
                        pkt_dport == dst_port and
                        (protocol is None or protocol.upper() in pkt_proto)):

                        self.anomalies.append(pkt)
                        break
                anomaly_signature = (a['src_ip'], a['dst_ip'], a['label'])
                
                if anomaly_signature not in self.unique_anomalies:
                    self.unique_anomalies.add(anomaly_signature)
                    current_time = datetime.now().strftime("%H:%M:%S")
                    self.networkLog.append(f"{current_time} - An anomaly occurred")

                    # Add to anomaly table
                    row_position = self.ui.tableWidget_4.rowCount()
                    self.ui.tableWidget_4.insertRow(row_position)

                    row_color = "rgba(255, 140, 140, 150)"
                    qcolor = self.get_qcolor(row_color)

                    items = [
                        QTableWidgetItem(current_time),
                        QTableWidgetItem(a['src_ip']),
                        QTableWidgetItem(a['dst_ip']),
                        QTableWidgetItem(str(a['label']))
                    ]

                    for item in items:
                        item.setBackground(qcolor)
                    for col, item in enumerate(items):
                        self.ui.tableWidget_4.setItem(row_position, col, item)
        except Exception as e:
            print(f"Error in IDStick function: {e}")