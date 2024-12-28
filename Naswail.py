import sys
import numpy as np
import time
import multiprocessing
from sklearn.svm import OneClassSVM
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QTextEdit, QSplitter, QHBoxLayout, QPushButton, QLineEdit, QLabel, QDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from scapy.all import sniff, wrpcap
from statistics import mean, median, mode, stdev, variance
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import mean_squared_error, r2_score
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from datetime import datetime, timedelta

time_series = {}

class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(object)

    def run(self):
        sniff(prn=self.emit_packet, store=False)

    def emit_packet(self, packet):
        self.packet_captured.emit(packet)

class PacketSnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Naswail")
        self.setGeometry(100, 100, 1000, 700)

        # Main layout
        main_layout = QVBoxLayout()
        self.central_widget = QWidget()
        self.central_widget.setLayout(main_layout)
        self.setCentralWidget(self.central_widget)

        # Splitter to divide the screen into 2 parts horizontally
        horizontal_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(horizontal_splitter)

        # First vertical splitter (left side)
        left_splitter = QSplitter(Qt.Orientation.Vertical)
        horizontal_splitter.addWidget(left_splitter)

        # Second vertical splitter (right side)
        right_splitter = QSplitter(Qt.Orientation.Vertical)
        horizontal_splitter.addWidget(right_splitter)

        # bottom panel for controls and stats
        control_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by IP or Protocol")
        self.filter_button = QPushButton("Apply Filter")
        self.filter_button.clicked.connect(self.apply_filter)
        self.export_button = QPushButton("Export Packets")
        self.export_button.clicked.connect(self.export_packets)
        self.stats_label = QLabel("Packets: 0 | TCP: 0 | UDP: 0 | ICMP: 0")

        #Add Widgets
        control_layout.addWidget(self.filter_input)
        control_layout.addWidget(self.filter_button)
        control_layout.addWidget(self.export_button)
        control_layout.addWidget(self.stats_label)
        main_layout.addLayout(control_layout)

        # Table to display packets
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(4)
        self.packet_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Protocol"])
        self.packet_table.cellClicked.connect(self.display_packet_details)
        left_splitter.addWidget(self.packet_table)

        # Text edit to display detailed packet info
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        left_splitter.addWidget(self.packet_details)

        # Data storage for packets and stats
        self.packets = []
        self.filtered_packets = []
        self.packet_features = []
        self.new_packet_features = []
        self.packet_stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0}
        self.model = LinearRegression()
        self.anmodel = OneClassSVM(kernel='rbf', gamma=0.1, nu=0.1)


        # Bandwidth tracking
        self.bandwidth_data = []  # List to store bandwidth usage over time

        # Start sniffing packets
        self.sniffer_thread = PacketSnifferThread()
        self.sniffer_thread.packet_captured.connect(self.process_packet)
        self.sniffer_thread.start()

        # Timer for updating stats
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)
        self.ct = 0

        # Create a Matplotlib figure and canvas for the top-right quarter
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)

        # Create layout for the right panel
        right_layout = QVBoxLayout()
        right_layout.addWidget(self.canvas)

        # Add "Show Pie Chart" button
        self.piechart_button = QPushButton("Show Pie Chart")
        self.piechart_button.clicked.connect(self.create_pie_chart)
        right_layout.addWidget(self.piechart_button)

        # Add "Show Histogram" button
        self.histogram_button = QPushButton("Show Histogram")
        self.histogram_button.clicked.connect(self.create_histogram_chart)
        right_layout.addWidget(self.histogram_button)

        # Add "Show Statistics" button
        self.stats_button = QPushButton("Show Mean, Median, etc.")
        self.stats_button.clicked.connect(self.show_stats)
        right_layout.addWidget(self.stats_button)

        # Add "Show Time Series" button
        self.timeseries_button = QPushButton("Show Time Series")
        self.timeseries_button.clicked.connect(self.create_time_series_chart)
        right_layout.addWidget(self.timeseries_button)

        # Bandwidth button
        self.bandwidth_button = QPushButton("Bandwidth Usage")
        self.bandwidth_button.clicked.connect(self.plot_bandwidth)
        right_layout.addWidget(self.bandwidth_button)

        #time-series labels
        self.times = []
        self.counts = []

        self.timer = QTimer(self)  # Timer instance
        self.timer.timeout.connect(self.tick)  # Connect the timer to a function
        self.timer.start(1000) 

        self.anomalies = []

        self.futureTraffic = 0
        self.r2 = 0
        
        # Create a QWidget to hold the layout
        right_widget = QWidget()
        right_widget.setLayout(right_layout)

        # Add the QWidget to the right_splitter
        right_splitter.addWidget(right_widget)

        #Bottom-Right Quarter
        self.MLPrediction = QVBoxLayout()
        
        self.noHours = QLineEdit("After How Many Hours?", self)
        self.estimate = QPushButton("Estimate Future Traffic", self)
        self.estimate.clicked.connect(self.pred_traffic)
        self.dispPred = QTextEdit()
        #self.dispPred.setText(str(self.futureTraffic) + str(self.r2))
        self.MLPrediction.addWidget(self.noHours)
        self.MLPrediction.addWidget(self.estimate)
        self.MLPrediction.addWidget(self.dispPred)
        
        right_widget2 = QWidget()
        right_widget2.setLayout(self.MLPrediction)
        right_splitter.addWidget(right_widget2)

        # Table to display suspicious packets
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(4)
        self.anomalies_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Protocol"])
        self.anomalies_table.cellClicked.connect(self.display_packet_details)
        right_splitter.addWidget(self.anomalies_table)

    def create_pie_chart(self):
        """Display a pie chart of the statistics."""
        self.figure.clear()
        ax = self.figure.add_subplot(111)

        labels = ["TCP", "UDP", "ICMP", "Other"]
        values = [
            self.packet_stats["tcp"],
            self.packet_stats["udp"],
            self.packet_stats["icmp"],
            self.packet_stats["total"] - (self.packet_stats["tcp"] + self.packet_stats["udp"] + self.packet_stats["icmp"])
        ]
        ax.pie(values, labels=labels, autopct='%1.1f%%', colors=['blue', 'orange', 'green', 'red'])
        ax.set_title("Protocol Usage Distribution")

        self.canvas.draw()

    def create_histogram_chart(self):
        """Display a histogram of the statistics."""
        self.figure.clear()
        ax = self.figure.add_subplot(111)

        labels = ["TCP", "UDP", "ICMP", "Other"]
        values = [
            self.packet_stats["tcp"],
            self.packet_stats["udp"],
            self.packet_stats["icmp"],
            self.packet_stats["total"] - (self.packet_stats["tcp"] + self.packet_stats["udp"] + self.packet_stats["icmp"])
        ]
        ax.bar(labels, values, color=['blue', 'orange', 'green', 'red'], edgecolor='black', alpha=0.7)
        ax.set_title("Protocol Histogram")
        ax.set_xlabel("Protocol")
        ax.set_ylabel("Frequency")

        self.canvas.draw()

    def show_stats(self):
        """Display mean, median, mode, standard deviation, and variance."""
        self.figure.clear()
        counts = [
            self.packet_stats["tcp"],
            self.packet_stats["udp"],
            self.packet_stats["icmp"],
            self.packet_stats["total"] - (self.packet_stats["tcp"] + self.packet_stats["udp"] + self.packet_stats["icmp"])
        ]

        mean_val = mean(counts)
        median_val = median(counts)
        mode_val = mode(counts) if len(set(counts)) != len(counts) else "No mode"
        stdev_val = stdev(counts) if len(counts) > 1 else "N/A"
        variance_val = variance(counts) if len(counts) > 1 else "N/A"

        stats_text = (f"Mean: {mean_val}\n"
                        f"Median: {median_val}\n"
                        f"Mode: {mode_val}\n"
                        f"Standard Deviation: {stdev_val}\n"
                        f"Variance: {variance_val}")

        ax = self.figure.add_subplot(111)
        ax.text(0.5, 0.5, stats_text, ha='center', va='center', fontsize=12)
        ax.axis('off')

        self.canvas.draw()

    def create_time_series_chart(self):
        """Display a time series graph of packet capture over time."""
        self.figure.clear()
        ax = self.figure.add_subplot(211)

        self.times = list(time_series.keys())
        self.counts = list(time_series.values())

        ax.plot(self.times, self.counts, marker='o', linestyle='-', color='blue')
        ax.set_title("Packets Over Time")
        ax.set_xlabel("Time")
        ax.set_ylabel("Packet Count")
        ax.tick_params(axis='x', rotation=45)

        self.canvas.draw()

    def plot_bandwidth(self):
        self.figure.clear()
        ax = self.figure.add_subplot(211)

        # Prepare the data for the graph
        if self.bandwidth_data:
            times, bandwidth = zip(*self.bandwidth_data)  # Split the data into times and bandwidth
        else:
            times, bandwidth = [], []  # Handle case with no data

        # Plot the data as a line graph
        ax.plot(times, bandwidth, marker='o', linestyle='-', color='blue')

        # Add titles and labels for clarity
        ax.set_title("Bandwidth Usage Over Time")
        ax.set_xlabel("Time")
        ax.set_ylabel("Bytes per Second")
        ax.tick_params(axis='x', rotation=45)  # Rotate x-axis labels for better readability

        # Redraw the canvas to display the updated graph
        self.canvas.draw()

    def process_packet(self, packet):
        """Process each captured packet and add it to the table."""
        try:
            # Extract packet information
            timestamp = packet.time
            readable_time = datetime.fromtimestamp(timestamp).strftime("%I:%M:%S %p")
            src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
            protocol = packet.sprintf("%IP.proto%") if packet.haslayer("IP") else "Other"
            packet_length = len(packet)

            self.new_packet_features.append([packet_length, timestamp, protocol])
            
            if(self.ct>60):
                prediction = self.anmodel.predict([self.packet_features])
        
                if(prediction == -1):
                    self.anomalies.append(packet)

            # Update stats
            self.packet_stats["total"] += 1
            if protocol == "tcp":
                self.packet_stats["tcp"] += 1
            elif protocol == "udp":
                self.packet_stats["udp"] += 1
            elif protocol == "icmp":
                self.packet_stats["icmp"] += 1

            # Add to packets list
            self.packets.append(packet)

            # Add to table
            row_position = self.packet_table.rowCount()
            self.packet_table.insertRow(row_position)
            self.packet_table.setItem(row_position, 0, QTableWidgetItem(readable_time))
            self.packet_table.setItem(row_position, 1, QTableWidgetItem(src_ip))
            self.packet_table.setItem(row_position, 2, QTableWidgetItem(dst_ip))
            self.packet_table.setItem(row_position, 3, QTableWidgetItem(protocol))

            #Add to timestamp
            timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S")
            time_series[timestamp] = len(self.packets)

            # Update bandwidth data
            if len(self.bandwidth_data) == 0 or self.bandwidth_data[-1][0] != readable_time:
                self.bandwidth_data.append((readable_time, len(packet)))
            else:
                self.bandwidth_data[-1] = (readable_time, self.bandwidth_data[-1][1] + len(packet))


        except Exception as e:
            print(f"Error processing packet: {e}")

    def display_packet_details(self, row, column):
        """Display detailed information about the selected packet."""
        try:
            packet = self.packets[row]
            details = packet.show(dump=True)  # Get packet details as a string
            self.packet_details.setText(details)
        except Exception as e:
            self.packet_details.setText(f"Error displaying packet details: {e}")

    def apply_filter(self):
        """Filter packets based on user input."""
        filter_text = self.filter_input.text().lower()
        self.packet_table.setRowCount(0)  # Clear the table

        self.filtered_packets = []
        for packet in self.packets:
            src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
            protocol = packet.sprintf("%IP.proto%") if packet.haslayer("IP") else "Other"

            if filter_text in src_ip.lower() or filter_text in dst_ip.lower() or filter_text in protocol.lower():
                self.filtered_packets.append(packet)

                row_position = self.packet_table.rowCount()
                self.packet_table.insertRow(row_position)
                self.packet_table.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(packet.time).strftime("%I:%M:%S %p")))
                self.packet_table.setItem(row_position, 1, QTableWidgetItem(src_ip))
                self.packet_table.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                self.packet_table.setItem(row_position, 3, QTableWidgetItem(protocol))

    def pred_traffic(self):
        #Train Regression Model
        if(len(self.packets) > 300):
            
            X = [(datetime.strptime(timestamp, "%H:%M:%S") - datetime.strptime(list(time_series.keys())[0], "%H:%M:%S")).total_seconds() for timestamp in time_series.keys()]

            X = np.array(list(map(int, X))).reshape(-1, 1)
            y = list(time_series.values())
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, train_size=0.8, random_state=42)
            self.model.fit(X_train, y_train)

            noHours = int(self.noHours.text())
            currentTime = datetime.now()
            oneHourLater = []
            oneHourLater.append(currentTime.second + 3600 * int(self.noHours.text()))
            oneHourLater = np.array(oneHourLater).reshape(-1, 1)

            self.futureTraffic = self.model.predict(oneHourLater)
            y_pred = self.model.predict(X_test)
            self.r2 = r2_score(y_test, y_pred)

            self.dispPred.setText("Estimated Packet Amount: " + str(self.futureTraffic - len(self.packets)) + "\nPrediciton Accuracy: " + str(self.r2) + "%")
            print(self.futureTraffic - len(self.packets))
            print(self.r2)
            self.update()
    
    def export_packets(self):
        """Export captured packets to a file."""
        try:
            wrpcap("captured_packets.pcap", self.packets)
            print("Packets exported successfully.")
        except Exception as e:
            print(f"Error exporting packets: {e}")

    def update_stats(self):
        """Update the statistics label."""
        self.stats_label.setText(f"Packets: {self.packet_stats['total']} | TCP: {self.packet_stats['tcp']} | UDP: {self.packet_stats['udp']} | ICMP: {self.packet_stats['icmp']}")

    def tick(self):
        self.ct += 1
    
    def classifierPreprocessing(self):
        if(self.ct %10 == 0):
            self.packet_features.extend(self.new_packet_features)
            self.new_packet_features = []
            X_train = np.array(self.packet_features)
            self.anmodel.fit(X_train)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec())
