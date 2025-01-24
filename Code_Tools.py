import sys
import numpy as np
import pandas as pd
import time
import multiprocessing
import psutil
import os
import ipaddress
from datetime import datetime, timedelta
from sklearn.svm import OneClassSVM
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from scapy.all import sniff, IP, TCP, UDP 

from statistics import mean, median, mode, stdev, variance
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import mean_squared_error, r2_score
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from UI_Tools import Ui_Naswail_Tool
class NetworkActivity:
    def __init__(self,ui):
        self.packetsysobj=None
        self.ui=ui
    def set_packetobj(self, packetsysobj):
        self.packetsysobj=packetsysobj
    def display(self):
        try:
            formatted_content=[]
            for list_of_activity in self.packetsysobj.list_of_activity:
                    loa=list_of_activity.activity
                    formatted_content.append(loa) 

            model = QStringListModel()
            model.setStringList(formatted_content)
            self.ui.listView_2.setModel(model)
            self.ui.listView_2.setStyleSheet("QListView { font-size: 16px; }")
        except Exception as e:
            print(e) 
class RegressionPrediction:
    def __init__(self,ui, packets):
        self.ui=ui
        self.futureTraffic = []
        self.r2 = 0
        self.noHours = None
        self.packets = packets
        self.model = LinearRegression()
        print(self.packets)
        
    def pred_traffic(self, time_series):
        #Train Regression Model
        try:
            if(len(self.packets) > 10):
                #print(datetime.strptime(list(time_series.keys())[0], "%H:%M:%S"))
                X = [timestamp - list(time_series.keys())[0] for timestamp in time_series.keys()]

                X = np.array(list(map(int, X))).reshape(-1, 1)
                y = list(time_series.values())
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, train_size=0.8, random_state=42)
                self.model.fit(X_train, y_train)

                currentTime = datetime.now()
                TimeLater = []
                Intervals = [0, 1, 3, 6, 12, 24]
                for i in range(6):
                    if(i != 0):
                        TimeLater.append(currentTime.second + 3600 * Intervals[i])
                    else:
                        TimeLater.append((currentTime.second + 3600 * self.noHours) if self.noHours is not None else 0)
                
                TimeLater = np.array(TimeLater).reshape(-1, 1)

                self.futureTraffic = self.model.predict(TimeLater)
                for i in range(len(self.futureTraffic)):
                    self.futureTraffic[i] -= len(self.packets)
                y_pred = self.model.predict(X_test)
                self.r2 = r2_score(y_test, y_pred)

                print(self.r2)
        except Exception as e:
            print(e)

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

    def display_graph(self):
        try:
            counts = []
            labels = ["Current", "Desired Time", "+1 Hours", "+3 Hours", "+6 Hours", "+12 Hours" + "+24 Hours"]
            counts.append(len(self.packets))
            for i in range(0, len(self.futureTraffic) - 1):
                counts.append(int(self.futureTraffic[i]))

            # Create the graph
            figure = Figure(figsize=(4, 4))
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            ax.plot(labels, counts, marker='o', linestyle='-', color='b')
            ax.set_title("Prediction Graph")
            ax.set_xlabel("Time Intervals")
            ax.set_ylabel("Estimated Packet Amount")
            canvas.draw()

            if self.ui.widget.layout() is None:
                layout = QVBoxLayout(self.ui.widget)
                self.ui.widget.setLayout(layout)
            else:
                layout = self.ui.widget.layout()
                # Clear the previous widgets in the layout
                for i in range(layout.count()):
                    child = layout.itemAt(i).widget()
                    if child is not None:
                        child.deleteLater()

            layout.addWidget(canvas)
        except Exception as e:
            print(e)

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
            if not self.packetobj.filterapplied:  # Check if the filter is not applied
                packet = self.packetobj.packets[row]
                
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
            """Filter packets based on selected protocols, source/destination IPs, and ComboBox selection."""
            # Map checkbox states to protocol names
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
            

            # Check if all protocol filters are unchecked and both src and dst filters are empty
            src_filter = self.ui.lineEdit_8.text().strip()
            dst_filter = self.ui.lineEdit_9.text().strip()

                # Check if all protocol filters are unchecked and both src and dst filters are empty
            if not any(protocol_filters.values()) and not src_filter and not dst_filter:
                    print("No protocols selected, and both source and destination filters are empty.")
                    self.filterapplied=False
                    self.ui.tableWidget.setRowCount(0)
                    self.process_packet_index=0
                    self.pcap_process_packet_index=0
                    return  # Or handle this case appropriately
                #
            self.filterapplied = True

            # Determine which protocols to filter
            selected_protocols = [protocol for protocol, checked in protocol_filters.items() if checked]
            # Get the source and destination IP filters
            src_filter = self.ui.lineEdit_8.text().strip()
            dst_filter = self.ui.lineEdit_9.text().strip()
            # Get ComboBox selection
            combo_selection = self.ui.comboBox_3.currentText()  # 'Inside' or 'Outside'
            # Clear the table before adding filtered packets
            self.ui.tableWidget.setRowCount(0)

            # Filter packets
            self.filtered_packets = []
            x = self.anomalies
            
            for packet in x:
                src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                protocol = self.packetobj.get_protocol(packet)

                # Determine if source/destination IPs are local
                src_is_local = self.packetobj.is_local_ip(src_ip)
                dst_is_local = self.packetobj.is_local_ip(dst_ip)

                # Check if the packet matches the selected protocols
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

                # Include packet if it matches all criteria
                if protocol_match and src_match and dst_match and ip_match:

                    self.filtered_packets.append(packet)
                    macsrc = packet["Ethernet"].src if packet.haslayer("Ethernet") else "N/A"
                    macdst = packet["Ethernet"].dst if packet.haslayer("Ethernet") else "N/A"
                    # Extract packet length
                    packet_length = int(len(packet))
                    payload = packet["Raw"].load if packet.haslayer("Raw") else "N/A"

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
            
        
        def add_error_packet(self, packet):
                self.packetobj=packet
        

        def display(self):
                try:
                    self.ui.tableWidget_6.setRowCount(0)
                    for packet in self.packetobj.corrupted_packet:
                            
                            #print("in error packet")
                            src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                            dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                            protocol = self.packetobj.get_protocol(packet)
                            layer = "UDP" if packet.haslayer("UDP") else "TCP" if packet.haslayer("TCP") else "Other"
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
                            row_position = self.ui.tableWidget_6.rowCount()
                            self.ui.tableWidget_6.insertRow(row_position)
                            self.ui.tableWidget_6.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")))
                            self.ui.tableWidget_6.setItem(row_position, 1, QTableWidgetItem(src_ip))
                            self.ui.tableWidget_6.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                            self.ui.tableWidget_6.setItem(row_position, 3, QTableWidgetItem(protocol))
                            self.ui.tableWidget_6.setItem(row_position, 4, QTableWidgetItem(layer))
                                    # Add MAC addresses and port info to the table
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
        self.main_window = main_window  # Reference to the main window

        self.ui = Ui_Naswail_Tool()  # Create an instance of the UI class
        self.ui.setupUi(self)  # Set up the UI for this widget
        self.init_ui()
        self.ErrorPacketSystemobj = ErrorPacketSystem(self.ui)
        self.RegPred = RegressionPrediction(self.ui, self.main_window.PacketSystemobj.packets)
        self.SuAn = SuspiciousAnalysis(self.ui, self.main_window.PacketSystemobj.anomalies, self.main_window.PacketSystemobj)
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

        self.ui.tableWidget.setColumnCount(10)
        self.ui.tableWidget.setHorizontalHeaderLabels(
            ["Timestamp", "Source IP", "Destination IP", "MAC Src", "MAC Dst", "Src Port", "Dst Port", "Protocol", "Length", "Payload"]
        )
        self.ui.tableWidget.cellClicked.connect(self.SuAn.display_packet_details)
        self.ui.tableWidget.cellClicked.connect(self.SuAn.decode_packet)   # UDP
        self.ui.checkBox_21.stateChanged.connect(self.SuAn.apply_filter)    # TCP
        self.ui.checkBox_22.stateChanged.connect(self.SuAn.apply_filter)    # ICMP
        self.ui.checkBox_23.stateChanged.connect(self.SuAn.apply_filter)    # DNS
        self.ui.checkBox_24.stateChanged.connect(self.SuAn.apply_filter)    # DHCP
        self.ui.checkBox_28.stateChanged.connect(self.SuAn.apply_filter)    # HTTP
        self.ui.checkBox_25.stateChanged.connect(self.SuAn.apply_filter)    # HTTPS
        self.ui.checkBox_26.stateChanged.connect(self.SuAn.apply_filter)    # TELNET
        self.ui.checkBox_30.stateChanged.connect(self.SuAn.apply_filter)    # FTP
        self.ui.checkBox_27.stateChanged.connect(self.SuAn.apply_filter)
        self.ui.checkBox_29.stateChanged.connect(self.SuAn.apply_filter)      # Other
        self.ui.pushButton_11.clicked.connect(self.SuAn.apply_filter)
        self.ui.pushButton_7.clicked.connect(self.networkactobj.display)
        # Initialize and start the timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.ttTime)
        self.timer.start(1000)  # Call every 1000 milliseconds (1 second)
        self.sec = 0
        
        
        
    def init_ui(self):
        self.showMaximized()
        self.ui.pushButton_4.clicked.connect(self.show_main_window)
        self.ui.pushButton_2.clicked.connect(self.show_analysis_window)
        

    def ttTime(self):
        """Call the display method of the ErrorPacketSystem every second."""
        self.ErrorPacketSystemobj.display()
        self.SuAn.display()
        if(self.sec % 30 == 0):
            self.RegPred.pred_traffic(self.main_window.time_series)
            if(self.RegPred.r2 > 0.50):
                self.RegPred.display()
                self.RegPred.display_graph()
                pass
        self.sec += 1

    def resetfilter(self):
        try:
            self.SuAn.process_packet_index=0
            self.SuAn.pcap_process_packet_index=0
            self.ui.tableWidget.setRowCount(0)
            self.SuAn.filterapplied=False
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
            self.SuAn.filterapplied = False
        except Exception as e:
            print(f"Error in resetfilter function: {e}")

    def show_analysis_window(self):
        """Show the analysis window and hide this widget."""
        self.secondary_widget = self.main_window.open_analysis()
        self.hide()

    def show_main_window(self):
        """Show the main window and hide this widget."""
        self.main_window.show()
        self.hide()



if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = Window_Tools()
    main_window.show()
    sys.exit(app.exec())
