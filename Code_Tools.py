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

                            print("in error packet")
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

        self.ErrorPacketSystemobj.add_error_packet(self.main_window.PacketSystemobj)
        self.ErrorPacketSystemobj.display()
        self.setWindowTitle("Secondary Widget")
        self.ui.tableWidget_6.setHorizontalHeaderLabels(
            ["Timestamp", "Source", "Destination", "Protocol", "Layer", "MAC Src", "MAC Dst", "Src Port", "Dst Port", "Length", "IP Version"]
        )

        # Initialize and start the timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.ttTime)
        self.timer.start(1000)  # Call every 1000 milliseconds (1 second)

    def init_ui(self):
        self.showMaximized()
        self.ui.pushButton_4.clicked.connect(self.show_main_window)
        self.ui.pushButton_2.clicked.connect(self.show_analysis_window)

    def ttTime(self):
        """Call the display method of the ErrorPacketSystem every second."""
        self.ErrorPacketSystemobj.display()

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
