import sys
import numpy as np
import threading
from datetime import datetime, timedelta
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from scapy.all import sniff, IP, TCP, UDP
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from datetime import datetime, timedelta
from UI_Tools import Ui_Naswail_Tool
import time

class NetworkActivity:
    def __init__(self,ui):
        self.packetsysobj=None
        self.ui=ui
        self.filecontent=""
    def set_packetobj(self, packetsysobj):
        self.packetsysobj=packetsysobj
    def display(self):
        try:
            self.packetsysobj.Update_Network_Summary()
            self.filecontent=""
            formatted_content=[]
            for list_of_activity  in self.packetsysobj.list_of_activity:
                    loa=list_of_activity.activity
                    formatted_content.append(loa) 
                    self.filecontent+=loa+"\n"

            model = QStringListModel()
            model.setStringList(formatted_content)
            self.ui.listView_2.setModel(model)
            self.ui.listView_2.setStyleSheet("QListView { font-size: 16px; }")
        except Exception as e:
            print(e) 
    def save_activity(self):
        try:
            with open("data/Activity.txt", "w") as file:
                file.write(self.filecontent)
        except Exception as e:
            print(e)

class RegressionPrediction(threading.Thread):
    def __init__(self,ui, packets, time_series):
        super().__init__()
        self.ui=ui
        self.futureTraffic = []
        self.r2 = 0
        self.noHours = None
        self.packets = packets
        self.time_series = time_series
        self.model = LinearRegression()
        self.prediction_running = False  # Flag to prevent concurrent predictions
        self.last_update_time = 0  # Track last update time
        self.start()  
        
    def pred_traffic(self):
        #Train Regression Model
        try:
            # Prevent concurrent predictions
            if self.prediction_running:
                return
                
            self.prediction_running = True
            
            if(len(self.packets) > 10):
                # Convert time series to numpy arrays directly
                X = np.array([timestamp - list(self.time_series.keys())[0] for timestamp in self.time_series.keys()]).reshape(-1, 1)
                y = np.array(list(self.time_series.values()))
                
                # Use smaller test size for better performance with small datasets
                test_size = min(0.2, 10/len(self.packets))
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
                
                self.model.fit(X_train, y_train)

                currentTime = datetime.now()
                # Pre-allocate arrays for better performance
                Intervals = [0, 1, 3, 6, 12, 24]
                TimeLater = np.zeros(6)
                
                for i in range(6):
                    if i != 0:
                        TimeLater[i] = currentTime.second + 3600 * Intervals[i]
                    else:
                        TimeLater[i] = (currentTime.second + 3600 * self.noHours) if self.noHours is not None else 0
                
                # Reshape once
                TimeLater = TimeLater.reshape(-1, 1)
                
                # Make predictions
                self.futureTraffic = self.model.predict(TimeLater)
                self.futureTraffic = np.maximum(0, self.futureTraffic - len(self.packets))
                
                # Calculate R² score only if we have test data
                if len(X_test) > 0:
                    y_pred = self.model.predict(X_test)
                    self.r2 = r2_score(y_test, y_pred)
            
            self.prediction_running = False
        except Exception as e:
            self.prediction_running = False
            print(f"Error in prediction: {e}")

    def setHours(self):
        try:
            if(self.ui.lineEdit.text() is None or self.ui.lineEdit.text() is object):
                self.ui.lineEdit.setText("0")
            self.noHours = int(self.ui.lineEdit.text())
        except Exception as e:
            print(e)
    
    def display(self):
        try:
            #self.ui.tableWidget_3.setRowCount(0)
            #self.ui.tableWidget_3.setColumnCount(0)
            #############################################
            self.ui.tableWidget_3.setItem(0, 0, QTableWidgetItem(datetime.now().strftime("%I:%M:%S %p")))
            self.ui.tableWidget_3.setItem(0, 1, QTableWidgetItem(str(len(self.packets))))
            #############################################
            #self.ui.tableWidget_3.insertRow(1)
            if(self.noHours is not None):
                self.ui.tableWidget_3.setItem(1, 0, QTableWidgetItem(datetime.now().strftime("%I:%M:%S %p")))
                self.ui.tableWidget_3.setItem(1, 1, QTableWidgetItem(str(int(self.futureTraffic[0]))))
            #############################################
            #self.ui.tableWidget_3.insertRow(2)
            self.ui.tableWidget_3.setItem(2, 0, QTableWidgetItem((datetime.now() + timedelta(hours = 1)).strftime("%I:%M:%S %p")))
            self.ui.tableWidget_3.setItem(2, 1, QTableWidgetItem(str(int(self.futureTraffic[1]))))
            #############################################
            #self.ui.tableWidget_3.insertRow(3)
            self.ui.tableWidget_3.setItem(3, 0, QTableWidgetItem((datetime.now() + timedelta(hours = 3)).strftime("%I:%M:%S %p")))
            self.ui.tableWidget_3.setItem(3, 1, QTableWidgetItem(str(int(self.futureTraffic[2]))))
            #############################################
            #self.ui.tableWidget_3.insertRow(4)
            self.ui.tableWidget_3.setItem(4, 0, QTableWidgetItem((datetime.now() + timedelta(hours = 6)).strftime("%I:%M:%S %p")))
            self.ui.tableWidget_3.setItem(4, 1, QTableWidgetItem(str(int(self.futureTraffic[3]))))
            #############################################
            #self.ui.tableWidget_3.insertRow(5)
            self.ui.tableWidget_3.setItem(5, 0, QTableWidgetItem((datetime.now() + timedelta(hours = 12)).strftime("%I:%M:%S %p")))
            self.ui.tableWidget_3.setItem(5, 1, QTableWidgetItem(str(int(self.futureTraffic[4]))))
            #############################################
            #self.ui.tableWidget_3.insertRow(6)
            self.ui.tableWidget_3.setItem(6, 0, QTableWidgetItem((datetime.now() + timedelta(hours = 24)).strftime("%I:%M:%S %p")))
            self.ui.tableWidget_3.setItem(6, 1, QTableWidgetItem(str(int(self.futureTraffic[5]))))
        except Exception as e:
            print(e)

    def display_advanced_graph(self):
        try:
            # Only redraw if it's been a while since the last update
            current_time = time.time()
            if current_time - self.last_update_time < 5:  # Don't update more than once every 5 seconds
                return
                
            self.last_update_time = current_time
                
            # Create a figure with better proportions and smaller size for performance
            figure = Figure(figsize=(8, 6))
            canvas = FigureCanvas(figure)
            
            # Main plot for predictions
            ax1 = figure.add_subplot(211)  # 2 rows, 1 column, first plot
            
            # Prediction data
            pred_labels = ["Now", "Desired", "+1h", "+3h", "+6h", "+12h", "+24h"]
            pred_times = list(range(len(pred_labels)))
            pred_values = [len(self.packets)] + [int(val) for val in self.futureTraffic]
            
            # Plot predictions as a line with points
            ax1.plot(pred_times, pred_values, marker='o', color='#40E0D0', linewidth=2, label='Prediction')
            
            # Add confidence region (simplified for performance)
            confidence = 0.1 * np.array(pred_values) * (1 + (1-max(0.1, self.r2))*2)
            ax1.fill_between(pred_times, pred_values - confidence, pred_values + confidence, 
                           color='#40E0D0', alpha=0.2)
            
            ax1.set_title(f"Network Traffic Prediction")
            ax1.set_ylabel("Packet Count")
            ax1.set_xticks(pred_times)
            ax1.set_xticklabels(pred_labels, rotation=15)
            ax1.grid(True, linestyle='--', alpha=0.5)
            
            # Percentage change plot
            ax2 = figure.add_subplot(212)  # 2 rows, 1 column, second plot
            
            # Calculate percent change
            base = pred_values[0] if pred_values[0] > 0 else 1
            pct_change = [(val - base)/base * 100 for val in pred_values]
            
            # Create color map
            colors = ['#40E0D0' if x >= 0 else '#FF6B6B' for x in pct_change]
            
            # Plot percentage changes
            bars = ax2.bar(pred_times, pct_change, color=colors, alpha=0.7)
            
            # Add value labels on bars (only for significant changes)
            for bar, pct in zip(bars, pct_change):
                if abs(pct) > 1.0:  # Only label significant changes
                    height = bar.get_height()
                    y_pos = height + 1 if height >= 0 else height - 5
                    ax2.text(bar.get_x() + bar.get_width()/2., y_pos,
                           f'{pct:.1f}%', ha='center', va='bottom', color='white', fontsize=8)
            
            ax2.set_title("Percentage Change in Traffic")
            ax2.set_ylabel("% Change")
            ax2.set_xticks(pred_times)
            ax2.set_xticklabels(pred_labels, rotation=15)
            ax2.grid(True, linestyle='--', alpha=0.5)
            ax2.axhline(y=0, color='white', linestyle='-', alpha=0.3)
            
            # Add R² score without using figure.text for better performance
            ax2.annotate(f"R²: {self.r2:.2f}", xy=(0.02, 0.02), xycoords='axes fraction', fontsize=8)
            
            figure.tight_layout()
            canvas.draw()
            
            # Update layout
            if self.ui.widget.layout() is None:
                layout = QVBoxLayout(self.ui.widget)
                self.ui.widget.setLayout(layout)
            else:
                layout = self.ui.widget.layout()
                for i in range(layout.count()):
                    child = layout.itemAt(i).widget()
                    if child is not None:
                        child.deleteLater()
            
            layout.addWidget(canvas)
        except Exception as e:
            print(f"Error in advanced graph: {e}")

    def run(self):
        print("Thread is running...")
        self.pred_traffic()

class SuspiciousAnalysis:
    def __init__(self,ui, anomalies, packet):
        self.ui=ui
        self.anomalies = anomalies
        self.packetobj= packet
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

    def decode_packet(self, row, column):
        try:
            if not self.packetobj.filterapplied:  
                packet = self.packetobj.packets[row]
                
                
                raw_content = bytes(packet)
                
                
                formatted_content = []
                for i in range(0, len(raw_content), 16):  #  16 bytes per line
                    chunk = raw_content[i:i + 16]
                    
                    # Hexadecimal representation
                    hex_part = " ".join(f"{byte:02x}" for byte in chunk)
                    
                    # ASCII representation 
                    ascii_part = "".join(
                        chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
                    )
                    
                    # Combine hex and ASCII parts
                    formatted_content.append(f"{hex_part:<48}  {ascii_part}")
                
               
                model = QStringListModel()
                model.setStringList(formatted_content)
                self.ui.listView_4.setModel(model)
        except Exception as e:
            print(f"Error displaying packet content with ASCII: {e}")

    def display_packet_details(self, row, column):
        try:
            if self.filterapplied==False:
                 packet = self.anomalies[row]
                 details = packet.show(dump=True)  # Get packet details as a string
                 detailslist = details.split("\n")
                 model = QStringListModel()
                 model.setStringList(detailslist)
                 self.ui.listView_3.setModel(model)
                        
            if self.filterapplied==True:
                packet = self.filtered_packets[row]
                details = packet.show(dump=True)  # Get packet details as a string
                detailslist = details.split("\n")
                model = QStringListModel()
                model.setStringList(detailslist)
                self.ui.listView_3.setModel(model)
        except Exception as e:
            print(f"Error displaying packet details: {e}")

    def apply_filter(self):
        try:
            
            protocol_filters = {
                "udp": self.ui.checkBox_21.isChecked(),
                "tcp": self.ui.checkBox_22.isChecked(),
                "icmp": self.ui.checkBox_23.isChecked(),
                "dns": self.ui.checkBox_24.isChecked(),
                "dhcp": self.ui.checkBox_28.isChecked(),
                "http": self.ui.checkBox_25.isChecked(),
                "https": self.ui.checkBox_26.isChecked(),
                "telnet": self.ui.checkBox_30.isChecked(),
                "ftp": self.ui.checkBox_27.isChecked(),
                "other": self.ui.checkBox_29.isChecked(),
            }
            

            
            src_filter = self.ui.lineEdit_8.text().strip()
            dst_filter = self.ui.lineEdit_9.text().strip()

                
            if not any(protocol_filters.values()) and not src_filter and not dst_filter:
                    print("No protocols selected, and both source and destination filters are empty.")
                    self.filterapplied=False
                    self.ui.tableWidget.setRowCount(0)
                    self.process_packet_index=0
                    self.pcap_process_packet_index=0
                    return  
                #
            self.filterapplied = True

            
            selected_protocols = [protocol for protocol, checked in protocol_filters.items() if checked]
            
            src_filter = self.ui.lineEdit_8.text().strip()
            dst_filter = self.ui.lineEdit_9.text().strip()
            
            combo_selection = self.ui.comboBox_3.currentText()  # 'Inside' or 'Outside'
            
            self.ui.tableWidget.setRowCount(0)

            
            self.filtered_packets = []
            x = self.anomalies
            
            for packet in x:
                src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                protocol = self.packetobj.get_protocol(packet)

                
                src_is_local = self.packetobj.is_local_ip(src_ip)
                dst_is_local = self.packetobj.is_local_ip(dst_ip)

                
                layer = "UDP" if packet.haslayer("UDP") else "TCP" if packet.haslayer("TCP") else "Other"
                protocol_match = protocol in selected_protocols if selected_protocols else True
                if "udp" in selected_protocols and layer == "UDP":
                 
                 protocol_match = True
                elif "tcp" in selected_protocols and layer == "TCP":
                    protocol_match = True
                elif "other" in selected_protocols and layer=="Other":
                    protocol_match=True
                

                # Check source and destination filters
                packet_time = datetime.fromtimestamp(float(packet.time))
                

                src_match = src_filter in src_ip if src_filter else True
                dst_match = dst_filter in dst_ip if dst_filter else True

                # Check ComboBox selection
                if combo_selection == "Inside":
                    ip_match = src_is_local and dst_is_local
                elif combo_selection == "Outside":
                    ip_match = not src_is_local or not dst_is_local
                else:
                    ip_match = True  # Default: no filter based on inside/outside

                
                if protocol_match and src_match and dst_match and ip_match:

                    self.filtered_packets.append(packet)
                    macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                    macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                
                    packet_length = int(len(packet))
                    payload = packet["Raw"].load if packet.haslayer("Raw") else "N/A"

                
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
                    self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(macsrc))
                    self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(macdst))
                    self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(str(sport)))
                    self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(str(dport)))
                    self.ui.tableWidget.setItem(row_position, 7, QTableWidgetItem(protocol))
                    self.ui.tableWidget.setItem(row_position, 8, QTableWidgetItem(str(packet_length)))
                    self.ui.tableWidget.setItem(row_position, 9, QTableWidgetItem(str(payload)))
            self.apply_filter=False
        except Exception as e:
            print(f"Error processing packet: {e}")

class ErrorPacketSystem:
        def __init__(self,ui):
            self.error_packets = []
            self.packetobj=None
            self.ui=ui
            self._last_packet_count = 0  # Track packet count for optimized updates
        
        def add_error_packet(self, packet):
                self.packetobj=packet
        

        def display(self):
                try:
                    # Only redraw if we have new packets
                    if self.packetobj and hasattr(self.packetobj, 'corrupted_packet'):
                        current_count = len(self.packetobj.corrupted_packet)
                        if current_count == self._last_packet_count:
                            return  # Skip redraw if no new packets
                        
                        # If table already has rows and we're just adding new ones
                        if self._last_packet_count > 0 and current_count > self._last_packet_count:
                            # Only process the new packets
                            start_idx = self._last_packet_count
                        else:
                            # Full redraw
                            self.ui.tableWidget_6.setRowCount(0)
                            start_idx = 0
                            
                        # Update our packet count tracker
                        self._last_packet_count = current_count
                        
                        # Add only the new packets
                        for idx in range(start_idx, current_count):
                            packet = self.packetobj.corrupted_packet[idx]
                            
                            # Extract data once to avoid redundant calls
                            has_ip = packet.haslayer("IP")
                            src_ip = packet["IP"].src if has_ip else "N/A"
                            dst_ip = packet["IP"].dst if has_ip else "N/A"
                            
                            has_eth = packet.haslayer("Ethernet")
                            macsrc = packet["Ethernet"].src if has_eth else "N/A"
                            macdst = packet["Ethernet"].dst if has_eth else "N/A"
                            
                            has_tcp = packet.haslayer("TCP")
                            has_udp = packet.haslayer("UDP")
                            
                            # Determine layer and protocol
                            if has_tcp:
                                layer = "tcp"
                                sport = packet["TCP"].sport
                                dport = packet["TCP"].dport
                            elif has_udp:
                                layer = "udp"
                                sport = packet["UDP"].sport
                                dport = packet["UDP"].dport
                            else:
                                layer = "Other"
                                sport = None
                                dport = None
                            
                            protocol = self.packetobj.get_protocol(packet)
                            packet_length = len(packet)
                            ip_version = "IPv6" if packet.haslayer("IPv6") else "IPv4" if has_ip else "N/A"
                            
                            # Format timestamp once
                            timestamp_str = datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")
                            
                            # Add row with optimized QTableWidgetItem creation
                            row_position = self.ui.tableWidget_6.rowCount()
                            self.ui.tableWidget_6.insertRow(row_position)
                            
                            # Populate row efficiently
                            self.ui.tableWidget_6.setItem(row_position, 0, QTableWidgetItem(timestamp_str))
                            self.ui.tableWidget_6.setItem(row_position, 1, QTableWidgetItem(src_ip))
                            self.ui.tableWidget_6.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                            self.ui.tableWidget_6.setItem(row_position, 3, QTableWidgetItem(protocol))
                            self.ui.tableWidget_6.setItem(row_position, 4, QTableWidgetItem(layer))
                            self.ui.tableWidget_6.setItem(row_position, 5, QTableWidgetItem(macsrc))
                            self.ui.tableWidget_6.setItem(row_position, 6, QTableWidgetItem(macdst))
                            self.ui.tableWidget_6.setItem(row_position, 7, QTableWidgetItem(str(sport) if sport else "N/A"))
                            self.ui.tableWidget_6.setItem(row_position, 8, QTableWidgetItem(str(dport) if dport else "N/A"))
                            self.ui.tableWidget_6.setItem(row_position, 9, QTableWidgetItem(str(packet_length)))
                            self.ui.tableWidget_6.setItem(row_position, 10, QTableWidgetItem(ip_version))
                except Exception as e:
                    print(f"Error in display function: {e}")

class Window_Tools(QWidget, Ui_Naswail_Tool):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window 

        self.ui = Ui_Naswail_Tool()  
        self.ui.setupUi(self)  
        self.init_ui()
        self.ErrorPacketSystemobj = ErrorPacketSystem(self.ui)
        self.RegPred = RegressionPrediction(self.ui, self.main_window.PacketSystemobj.packets, self.main_window.time_series)
        # self.SuAn = SuspiciousAnalysis(self.ui, self.main_window.PacketSystemobj.anomalies, self.main_window.PacketSystemobj)
        self.networkactobj=NetworkActivity(self.ui)
        self.networkactobj.set_packetobj(self.main_window.PacketSystemobj)
        self.networkactobj.display()

        self.ErrorPacketSystemobj.add_error_packet(self.main_window.PacketSystemobj)
        self.ErrorPacketSystemobj.display()
        self.setWindowTitle("Naswail - Tools")
        self.ui.tableWidget_6.setColumnCount(11)
        self.ui.tableWidget_6.setHorizontalHeaderLabels(
            ["Timestamp", "Source", "Destination", "Protocol", "Layer", "MAC Src", "MAC Dst", "Src Port", "Dst Port", "Length", "IP Version"]
        )

        self.ui.tableWidget_3.setColumnCount(2)
        self.ui.tableWidget_3.setRowCount(7)
        self.ui.tableWidget_3.setHorizontalHeaderLabels(["Time", "Packet Esitmate"])
        self.ui.tableWidget_3.setVerticalHeaderLabels(["Current", "Desired Time", "+ 1 Hour", "+ 3 Hour", "+ 6 Hour", "+ 12 Hour", "+ 24 Hour"])
        self.ui.pushButton.clicked.connect(self.RegPred.setHours)
        self.ui.pushButton_6.clicked.connect(self.resetfilter)

        # self.ui.tableWidget.setColumnCount(10)
        # self.ui.tableWidget.setHorizontalHeaderLabels(
        #     ["Timestamp", "Source IP", "Destination IP", "MAC Src", "MAC Dst", "Src Port", "Dst Port", "Protocol", "Length", "Payload"]
        # )
        # self.ui.tableWidget.cellClicked.connect(self.SuAn.display_packet_details)
        # self.ui.tableWidget.cellClicked.connect(self.SuAn.decode_packet)   # UDP
        # self.ui.checkBox_21.stateChanged.connect(self.SuAn.apply_filter)    # TCP
        # self.ui.checkBox_22.stateChanged.connect(self.SuAn.apply_filter)    # ICMP
        # self.ui.checkBox_23.stateChanged.connect(self.SuAn.apply_filter)    # DNS
        # self.ui.checkBox_24.stateChanged.connect(self.SuAn.apply_filter)    # DHCP
        # self.ui.checkBox_28.stateChanged.connect(self.SuAn.apply_filter)    # HTTP
        # self.ui.checkBox_25.stateChanged.connect(self.SuAn.apply_filter)    # HTTPS
        # self.ui.checkBox_26.stateChanged.connect(self.SuAn.apply_filter)    # TELNET
        # self.ui.checkBox_30.stateChanged.connect(self.SuAn.apply_filter)    # FTP
        # self.ui.checkBox_27.stateChanged.connect(self.SuAn.apply_filter)
        # self.ui.checkBox_29.stateChanged.connect(self.SuAn.apply_filter)      # Other
        # self.ui.pushButton_11.clicked.connect(self.SuAn.apply_filter)
        self.ui.pushButton_7.clicked.connect(self.networkactobj.display)
        self.ui.pushButton_5.clicked.connect(self.networkactobj.save_activity)
        
        # Use a more efficient timer strategy with reduced frequency
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.ttTime)
        self.timer.start(3000)  # Update every 3 seconds instead of every 1 second
        self.sec = 0
        
        # Set up a second, slower timer for heavy operations
        self.heavy_timer = QTimer(self)
        self.heavy_timer.timeout.connect(self.heavy_update)
        self.heavy_timer.start(15000)  # Run heavy operations every 15 seconds
        
        # Add cleanup when window is closed
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        
    def init_ui(self):
        self.showMaximized()
        self.ui.pushButton_4.clicked.connect(self.show_main_window)
        self.ui.pushButton_2.clicked.connect(self.show_analysis_window)
        self.ui.pushButton_8.clicked.connect(self.show_incidentresponse_window)
        

    def ttTime(self):
        # Only update the error packet display - light operation
        self.ErrorPacketSystemobj.display()
        self.sec += 3  # Increment by 3 since we're running every 3 seconds
    
    def heavy_update(self):
        # Handle heavy operations on a separate timer
        try:
            # Run prediction if not already running
            if not self.RegPred.prediction_running:
                self.RegPred.pred_traffic()
                if self.RegPred.r2 > 0.50:
                    self.RegPred.display()
                    self.RegPred.display_advanced_graph()
        except Exception as e:
            print(f"Error in heavy update: {e}")
            
    def closeEvent(self, event):
        # Cleanup resources when window is closed
        self.timer.stop()
        self.heavy_timer.stop()
        
        # Clean up matplotlib resources
        if self.ui.widget.layout() is not None:
            layout = self.ui.widget.layout()
            for i in range(layout.count()):
                child = layout.itemAt(i).widget()
                if child is not None:
                    child.deleteLater()
        
        # Accept the close event
        event.accept()

    def resetfilter(self):
        try:
            # self.SuAn.process_packet_index=0
            # self.SuAn.pcap_process_packet_index=0
            # self.ui.tableWidget.setRowCount(0)
            # self.SuAn.filterapplied=False
            self.ui.lineEdit_8.setText("")
            self.ui.lineEdit_9.setText("")
            checkboxes = [
                self.ui.checkBox_21,
                self.ui.checkBox_22,
                self.ui.checkBox_23,
                self.ui.checkBox_24,
                self.ui.checkBox_28,
                self.ui.checkBox_25,
                self.ui.checkBox_26,
                self.ui.checkBox_30,
                self.ui.checkBox_27,
                self.ui.checkBox_29,
            ]
            for checkbox in checkboxes:
                checkbox.setCheckState(Qt.CheckState.Unchecked)
            # self.SuAn.filterapplied = False
        except Exception as e:
            print(f"Error in resetfilter function: {e}")

    def show_analysis_window(self):
        try:
            self.secondary_widget = self.main_window.open_analysis()
            self.hide()
        except Exception as e:
            print(f"Error in show_analysis_window function: {e}")
    
    def show_incidentresponse_window(self):
        try:
            self.secondary_widget = self.main_window.open_incidentresponse()
            self.hide()
        except Exception as e:
            print(f"Error in show_incidentresponse_window function: {e}")

    def show_main_window(self):
        try:
            self.main_window.show()
            self.hide()
        except Exception as e:
            print(f"Error in show_main_window function: {e}")



if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = Window_Tools()
    main_window.show()
    sys.exit(app.exec())
