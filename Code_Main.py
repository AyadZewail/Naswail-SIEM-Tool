import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QTextEdit, QSplitter, QHBoxLayout, QPushButton, QLineEdit, QLabel, QDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from scapy.all import sniff, wrpcap
from statistics import mean, median, mode, stdev, variance
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from datetime import datetime

class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(object)

    def run(self):
        sniff(prn=self.emit_packet, store=False)

    def emit_packet(self, packet):
        self.packet_captured.emit(packet)

class PacketSnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 1000, 700)

        # Main layout
        main_layout = QVBoxLayout()
        self.central_widget = QWidget()
        self.central_widget.setLayout(main_layout)
        self.setCentralWidget(self.central_widget)

        # Splitter to separate table and details
        splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(splitter)

        # Top panel for controls and stats
        control_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by IP or Protocol")
        self.filter_button = QPushButton("Apply Filter")
        self.filter_button.clicked.connect(self.apply_filter)
        self.export_button = QPushButton("Export Packets")
        self.export_button.clicked.connect(self.export_packets)
        self.stats_label = QLabel("Packets: 0 | TCP: 0 | UDP: 0 | ICMP: 0")

        # Statistics button
        self.stats_button = QPushButton("Statistics")
        self.stats_button.clicked.connect(self.show_statistics)
        control_layout.addWidget(self.stats_button)

        # Bandwidth button
        self.bandwidth_button = QPushButton("Bandwidth Usage")
        self.bandwidth_button.clicked.connect(self.show_bandwidth_usage)
        control_layout.addWidget(self.bandwidth_button)

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
        splitter.addWidget(self.packet_table)

        # Text edit to display detailed packet info
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        splitter.addWidget(self.packet_details)

        # Data storage for packets and stats
        self.packets = []
        self.filtered_packets = []
        self.packet_stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0}

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

    class StatsWindow(QDialog):
        def __init__(self, stats, packets, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Statistics")
            layout = QVBoxLayout(self)

            # Create a Matplotlib figure
            self.figure = Figure()
            self.canvas = FigureCanvas(self.figure)
            layout.addWidget(self.canvas)

            # Add "Show Pie Chart" button
            self.piechart_button = QPushButton("Show Pie Chart")
            self.piechart_button.clicked.connect(self.create_pie_chart)
            layout.addWidget(self.piechart_button)

            # Add "Show Histogram" button
            self.histogram_button = QPushButton("Show Histogram")
            self.histogram_button.clicked.connect(self.create_histogram_chart)
            layout.addWidget(self.histogram_button)

            # Add "Show Statistics" button
            self.stats_button = QPushButton("Show Mean, Median, etc.")
            self.stats_button.clicked.connect(self.show_stats)
            layout.addWidget(self.stats_button)

            # Add "Show Time Series" button
            self.timeseries_button = QPushButton("Show Time Series")
            self.timeseries_button.clicked.connect(self.create_time_series_chart)
            layout.addWidget(self.timeseries_button)

            # Store stats and packets for use in the charts
            self.stats = stats
            self.packets = packets

        def create_pie_chart(self):
            """Display a pie chart of the statistics."""
            self.figure.clear()
            ax = self.figure.add_subplot(111)

            labels = ["TCP", "UDP", "ICMP", "Other"]
            values = [
                self.stats["tcp"],
                self.stats["udp"],
                self.stats["icmp"],
                self.stats["total"] - (self.stats["tcp"] + self.stats["udp"] + self.stats["icmp"])
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
                self.stats["tcp"],
                self.stats["udp"],
                self.stats["icmp"],
                self.stats["total"] - (self.stats["tcp"] + self.stats["udp"] + self.stats["icmp"])
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
                self.stats["tcp"],
                self.stats["udp"],
                self.stats["icmp"],
                self.stats["total"] - (self.stats["tcp"] + self.stats["udp"] + self.stats["icmp"])
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
            ax = self.figure.add_subplot(111)

            # Extract timestamps and group them by second
            time_series = {}
            for packet in self.packets:
                timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S")
                time_series[timestamp] = time_series.get(timestamp, 0) + 1

            times = list(time_series.keys())
            counts = list(time_series.values())

            ax.plot(times, counts, marker='o', linestyle='-', color='blue')
            ax.set_title("Packets Over Time")
            ax.set_xlabel("Time")
            ax.set_ylabel("Packet Count")
            ax.tick_params(axis='x', rotation=45)

            self.canvas.draw()

    class BandwidthWindow(QDialog):
        def __init__(self, bandwidth_data, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Bandwidth Usage")
            layout = QVBoxLayout(self)

            # Create a Matplotlib figure
            self.figure = Figure()
            self.canvas = FigureCanvas(self.figure)
            layout.addWidget(self.canvas)

            # Plot bandwidth usage over time
            self.figure.clear()
            ax = self.figure.add_subplot(211)

            # Prepare the data for the graph
            if bandwidth_data:
                times, bandwidth = zip(*bandwidth_data)  # Split the data into times and bandwidth
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

    def show_statistics(self):
        dialog = self.StatsWindow(self.packet_stats, self.packets, self)
        dialog.exec()

    def show_bandwidth_usage(self):
        dialog = self.BandwidthWindow(self.bandwidth_data, self)
        dialog.exec()

    def process_packet(self, packet):
        """Process each captured packet and add it to the table."""
        try:
            # Extract packet information
            timestamp = packet.time
            readable_time = datetime.fromtimestamp(timestamp).strftime("%I:%M:%S %p")
            src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
            protocol = packet.sprintf("%IP.proto%") if packet.haslayer("IP") else "Other"

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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    window.showMaximized()
    sys.exit(app.exec())
