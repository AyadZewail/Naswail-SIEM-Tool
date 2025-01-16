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
from scapy.all import *
from statistics import mean, median, mode, stdev, variance
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import mean_squared_error, r2_score
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from UI_Analysis import Ui_Naswail_Anlaysis


class Window_Analysis(QWidget, Ui_Naswail_Anlaysis):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window  # Reference to the main window

        self.ui = Ui_Naswail_Anlaysis()  # Create an instance of the UI class
        self.ui.setupUi(self)  # Set up the UI for this widget
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Secondary Widget")
        self.showMaximized()

        # Connect comboBox_2 selection change
        self.ui.comboBox_2.currentIndexChanged.connect(self.on_combobox_change)

        # Connect PushButton_5 click to display pie chart
        self.ui.pushButton_5.clicked.connect(self.display_pie_chart)
        self.ui.pushButton_4.clicked.connect(self.show_main_window)
        self.ui.pushButton_6.clicked.connect(self.display_histogram)
        self.ui.pushButton_7.clicked.connect(self.display_graph)
        self.ui.pushButton_9.clicked.connect(self.display_time_series)
        self.ui.pushButton_8.clicked.connect(self.display_heatmap)
     
        # Initialize a placeholder for selected option
        self.selected_option = "Protocols"
        self.display_graph()
        self.display_heatmap()
        self.display_histogram()
        self.display_pie_chart()
        self.display_time_series()

    def on_combobox_change(self):
        """Handle changes in comboBox_2."""
        self.selected_option = self.ui.comboBox_2.currentText()
        print(f"Selected option: {self.selected_option}")  # Debugging output

    def display_histogram(self):
        """Display a histogram based on the selected option."""
        if self.ui.comboBox_3.currentText()=="inside/outside":
            if self.selected_option=="inside/outside":

                total_inisde=self.main_window.PacketSystemobj.total_inside_packets
                total_outside=self.main_window.PacketSystemobj.total_outside_packets
                labels=["inside","Outside"]
                counts=[]
                counts.append(total_inisde)
                counts.append(total_outside)
                colors = ['#ff9999', '#66b3ff']
                figure = Figure(figsize=(4, 4))
                canvas = FigureCanvas(figure)
                ax = figure.add_subplot(111)
                ax.bar(labels, counts, color=['#ff9999', '#66b3ff'])
                ax.set_title("Inside/Outside Histogram")
                ax.set_xlabel("Inside/Outside")
                ax.set_ylabel("Count")
                canvas.draw()

            
        if self.ui.comboBox_3.currentText() == "Sensors":
            # Access packet stats from the main window
            sensors = self.main_window.SensorSystemobj.sen_info

            counts = []
            labels = []
            for s in range(0, len(self.main_window.SensorSystemobj.sen_info) - 1, 2):
                labels.append(sensors[s])
                counts.append(sensors[s + 1])

            # Create the histogram
            figure = Figure(figsize=(4, 4))
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            ax.bar(labels, counts, color=['#ff9999', '#66b3ff', '#99ff99', '#ffcc99'])
            ax.set_title("Sensors Histogram")
            ax.set_xlabel("Sensors")
            ax.set_ylabel("Count")
            canvas.draw()

        if self.ui.comboBox_3.currentText() == "Protocols":
            # Access packet stats from the main window
            packet_stats = self.main_window.PacketSystemobj.packet_stats

            # Define the protocols
            protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "Telnet", "DNS", "DHCP", "Other"]

            # Extract counts for each protocol
            counts = [
                packet_stats.get("tcp", 0),
                packet_stats.get("udp", 0),
                packet_stats.get("icmp", 0),
                packet_stats.get("http", 0),
                packet_stats.get("https", 0),
                packet_stats.get("ftp", 0),
                packet_stats.get("telnet", 0),
                packet_stats.get("dns", 0),
                packet_stats.get("dhcp", 0),
                packet_stats.get("total", 0)
                - sum(packet_stats.get(proto, 0) for proto in ["tcp", "udp", "icmp", "http", "https", "ftp", "telnet", "dns", "dhcp"]),
            ]

            # Create the histogram
            figure = Figure(figsize=(2, 2))  # Adjust size for more protocols
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            ax.bar(protocols, counts, color=['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#c5b0d5', '#ff7f0e', '#2ca02c', '#1f77b4', '#d62728', '#9467bd'])
            ax.set_title("Protocol Histogram")
            ax.set_xlabel("Protocol")
            ax.set_ylabel("Count")
            ax.set_xticks(range(len(protocols)))
            ax.set_xticklabels(protocols, rotation=45, ha="right")  # Rotate labels for readability
            figure.subplots_adjust(bottom=0.25, top=0.85)
            canvas.draw()

        # Clear the previous canvas in widget_2
        if self.ui.widget_2.layout() is None:
            layout = QVBoxLayout(self.ui.widget_2)
            self.ui.widget_2.setLayout(layout)
        else:
            layout = self.ui.widget_2.layout()
            # Clear the previous widgets in the layout
            for i in range(layout.count()):
                child = layout.itemAt(i).widget()
                if child is not None:
                    child.deleteLater()

        layout.addWidget(canvas)

    def display_graph(self):
        """Display a graph based on the selected option."""
        if self.ui.comboBox_4.currentText()=="Bandwidth":
           
           
           bandwidth_data = self.main_window.PacketSystemobj.bandwidth_data
           if bandwidth_data:
                    
                    # Capture the last 10 data points
                    last_10_data = bandwidth_data[-10:]
                    times, bandwidth = zip(*last_10_data)  # Split the data into times and bandwidth
                    
                    figure = Figure(figsize=(4, 4))
                    canvas = FigureCanvas(figure)
                    ax = figure.add_subplot(111)
                    ax.plot(times, bandwidth, marker='o', linestyle='-', color='b')
                    ax.set_title("Bandwidth Graph")
                    ax.set_xlabel("Time")
                    ax.set_ylabel("Bandwidth")
                    
                    # Rotate x-axis labels for better readability
                    ax.tick_params(axis='x', rotation=45)
                    figure.tight_layout()

                    canvas.draw()
            
        if self.ui.comboBox_4.currentText()=="inside/outside":
            total_inisde=self.main_window.PacketSystemobj.total_inside_packets
            total_outside=self.main_window.PacketSystemobj.total_outside_packets
            labels=["Inside","Outside"]
            counts=[]
            counts.append(total_inisde)
            counts.append(total_outside)
            figure = Figure(figsize=(4, 4))
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            ax.plot(labels, counts, marker='o', linestyle='-', color='b')
            ax.set_title("Inside/Outside Graph")
            ax.set_xlabel("Inside/Outside")
            ax.set_ylabel("Inside/Outside Count")
            canvas.draw()
        if self.ui.comboBox_4.currentText() == "Bandwidith":
            canvas = None  # Initialize canvas to avoid unbound variable error
            bandwidith = self.main_window.PacketSystemobj.bandwidth_data
            if not bandwidith:
                print("No bandwidth data available.")
                return

            labels, counts = zip(*bandwidith)  # Extract time and bandwidth values
            print("Labels:", labels)
            print("Counts:", counts)

            figure = Figure(figsize=(4, 4))
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            ax.plot(labels, counts, marker='o', linestyle='-', color='b')
            ax.set_title("Bandwidth Graph")
            ax.set_xlabel("Time")
            ax.set_ylabel("Bandwidth")
            canvas.draw()

            # Clear and update layout
            if self.ui.widget_3.layout() is None:
                layout = QVBoxLayout(self.ui.widget_3)
                self.ui.widget_3.setLayout(layout)
            else:
                layout = self.ui.widget_3.layout()
                for i in range(layout.count()):
                    child = layout.itemAt(i).widget()
                    if child is not None:
                        child.deleteLater()

            layout.addWidget(canvas)

        if self.ui.comboBox_4.currentText() == "Sensors":
            sensors = self.main_window.SensorSystemobj.sen_info
            counts = []
            labels = []
            for s in range(0, len(self.main_window.SensorSystemobj.sen_info) - 1, 2):
                labels.append(sensors[s])
                counts.append(sensors[s + 1])

            # Create the graph
            figure = Figure(figsize=(4, 4))
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            ax.plot(labels, counts, marker='o', linestyle='-', color='b')
            ax.set_title("Sensor Graph")
            ax.set_xlabel("Sensor")
            ax.set_ylabel("Sensor Packet Count")
            canvas.draw()

        if self.ui.comboBox_4.currentText() == "Protocols":
            packet_stats = self.main_window.PacketSystemobj.packet_stats
            protocols = ["TCP", "UDP", "ICMP", "Other"]
            counts = [
                packet_stats.get("tcp", 0),
                packet_stats.get("udp", 0),
                packet_stats.get("icmp", 0),
                packet_stats.get("total", 0)
                - sum(packet_stats.get(proto, 0) for proto in ["tcp", "udp", "icmp"]),
            ]

            # Create the graph
            figure = Figure(figsize=(4, 4))
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            ax.plot(protocols, counts, marker='o', linestyle='-', color='b')
            ax.set_title("Protocol Graph")
            ax.set_xlabel("Protocol")
            ax.set_ylabel("Count")
            canvas.draw()

        # Clear the previous canvas in widget_3
        if self.ui.widget_3.layout() is None:
            layout = QVBoxLayout(self.ui.widget_3)
            self.ui.widget_3.setLayout(layout)
        else:
            layout = self.ui.widget_3.layout()
            # Clear the previous widgets in the layout
            for i in range(layout.count()):
                child = layout.itemAt(i).widget()
                if child is not None:
                    child.deleteLater()

        layout.addWidget(canvas)

    def display_time_series(self):
 
        """Display a time series based on the selected option."""
        if self.ui.comboBox_6.currentText()=="Bandwidth":

            bandwidth_data = self.main_window.PacketSystemobj.bandwidth_data
            if bandwidth_data:

                # Capture the last 10 data points
                last_10_data = bandwidth_data[-10:]
                times, bandwidth = zip(*last_10_data)  # Split the data into times and bandwidth
                
                figure = Figure(figsize=(4, 4))
                canvas = FigureCanvas(figure)
                ax = figure.add_subplot(111)
                ax.plot(times, bandwidth, marker='o', linestyle='-', color='b')
                ax.set_title("Bandwidth Graph")
                ax.set_xlabel("Time")
                ax.set_ylabel("Bandwidth")
                
                # Rotate x-axis labels for better readability
                ax.tick_params(axis='x', rotation=45)
                figure.tight_layout()

                canvas.draw()
                if self.ui.widget_5.layout() is None:
                    layout = QVBoxLayout(self.ui.widget_5)
                    self.ui.widget_5.setLayout(layout)
                else:
                    layout = self.ui.widget_5.layout()
                    # Clear the previous widgets in the layout
                    for i in range(layout.count()):
                        child = layout.itemAt(i).widget()
                        if child is not None:
                            child.deleteLater()

                layout.addWidget(canvas)
            if self.ui.comboBox_6.currentText() == "Sensors":
                # Access sensor statistics from the main window
                sensors = self.main_window.SensorSystemobj.sen_info  # This is a list of tuples (sensor_name, packet_count)

                # Extract the times of the packets (assuming you need the times from packet_stats, adjust as needed)
                packet_stats = self.main_window.PacketSystemobj.packets  # Replace with your actual list of packets
                packet_times = [packet.time for packet in packet_stats]

                # Define the time range for the graph
                start_time = min(packet_times)
                end_time = max(packet_times)

                # Generate 10 intervals between the start and end times
                intervals = np.linspace(start_time, end_time, 11)  # 11 because we want 10 intervals

                # Initialize a list to hold the packet counts for each interval (for all sensors)
                packet_counts = [0] * 10

                # Count how many packets fall into each time interval
                for packet_time in packet_times:
                    for i in range(10):
                        if intervals[i] <= packet_time < intervals[i + 1]:
                            packet_counts[i] += 1
                            break  # Stop once we find the interval for the packet

                # Plot the results
                figure = plt.Figure(figsize=(6, 4))  # Define a larger figure size
                canvas = FigureCanvas(figure)
                ax = figure.add_subplot(111)

                # Convert the time intervals to a human-readable format (HH:MM:SS AM/PM)
                time_labels = [datetime.fromtimestamp(interval).strftime("%I:%M:%S %p") for interval in intervals[:-1]]

                # Plot the packet counts over time intervals
                ax.plot(intervals[:-1], packet_counts, label='sensor Packet Counts', marker='o')

                # Set labels and title
                ax.set_xlabel("Time interval")
                ax.set_ylabel("sensor Packet Count")
                ax.set_title("sensor Packet Counts Over Time")

                # Set x-axis ticks and labels
                ax.set_xticks(intervals[:-1])
                ax.set_xticklabels(time_labels, rotation=45, ha="right")  # Rotate labels and adjust alignment

                # Increase bottom margin for x-axis labels
                figure.subplots_adjust(bottom=0.2)

                # Add legend
                ax.legend()
                #Clear the previous canvas in widget_5
                if self.ui.widget_5.layout() is None:
                    layout = QVBoxLayout(self.ui.widget_5)
                    self.ui.widget_5.setLayout(layout)
                else:
                    layout = self.ui.widget_5.layout()
                    # Clear the previous widgets in the layout
                    for i in range(layout.count()):
                        child = layout.itemAt(i).widget()
                        if child is not None:
                            child.deleteLater()

                layout.addWidget(canvas)

        if self.ui.comboBox_6.currentText() == "Protocols":
                       
                            # Access packet statistics from the main window
                packet_stats = self.main_window.PacketSystemobj.packets  # Replace with your actual list of packets

                # Get the times of the packets
                packet_times = [packet.time for packet in packet_stats]

                # Define the time range for the graph
                start_time = min(packet_times)
                end_time = max(packet_times)

                # Generate 10 intervals between the start and end times
                intervals = np.linspace(start_time, end_time, 11)  # 11 because we want 10 intervals

                # Initialize a list to hold the packet counts for each interval
                packet_counts = [0] * 10

                # Count how many packets fall into each time interval
                for packet_time in packet_times:
                    for i in range(10):
                        if intervals[i] <= packet_time < intervals[i + 1]:
                            packet_counts[i] += 1
                            break  # Stop once we find the interval for the packet

                # Plot the results
                
                #
                figure = Figure(figsize=(4, 4))
                canvas = FigureCanvas(figure)
                ax = figure.add_subplot(111)

                # Plot the time series data (using a line plot)
                time_labels = [datetime.fromtimestamp(interval).strftime("%I:%M:%S %p") for interval in intervals[:-1]]
                ax.plot(intervals[:-1], packet_counts, label=' Packet Counts', marker='o')

                ax.set_xlabel("Time interval")
                ax.set_ylabel("Packet Count")
                ax.set_title("Packet Counts Over Time")
                ax.set_xticks(intervals[:-1])
                ax.set_xticklabels(time_labels, rotation=45)
                figure.subplots_adjust(bottom=0.2)  # Increase bottom margin for x-axis labels
                ax.legend()
            # Clear the previous canvas in widget_5
                if self.ui.widget_5.layout() is None:
                    layout = QVBoxLayout(self.ui.widget_5)
                    self.ui.widget_5.setLayout(layout)
                else:
                    layout = self.ui.widget_5.layout()
                    # Clear the previous widgets in the layout
                    for i in range(layout.count()):
                        child = layout.itemAt(i).widget()
                        if child is not None:
                            child.deleteLater()

                layout.addWidget(canvas)



    def display_heatmap(self):
            
            """Display a heatmap based on the selected option."""
            if self.ui.comboBox_5.currentText() == "Bandwidth":

                bandwidth_data = self.main_window.PacketSystemobj.bandwidth_data
                if bandwidth_data:
                    # Extract times and bandwidth values
                    times, bandwidth = zip(*bandwidth_data)
                    bandwidth = np.array(bandwidth)  # Convert bandwidth to numpy array

                    # Ensure bandwidth is 2D (even if just one row)
                    bandwidth = bandwidth.reshape(1, -1)  # Reshape into 2D array (1 row, n columns)

                    # Optional: Add more rows for better visualization
                    bandwidth = np.tile(bandwidth, (5, 1))  # Repeat row 5 times for better visual effect

                    # Create the figure and canvas
                    figure = Figure(figsize=(6, 4))
                    canvas = FigureCanvas(figure)
                    ax = figure.add_subplot(111)

                    # Plot the heatmap
                    cax = ax.matshow(bandwidth, cmap='coolwarm')

                    # Add colorbar for the heatmap
                    figure.colorbar(cax)

                    # Set tick labels for time (X-axis)
                    ax.set_xticks(range(len(times)))
                    ax.set_xticklabels(times, rotation=45, ha='right')  # Rotate for readability

                    # Set tick labels for Y-axis (Bandwidth rows)
                    ax.set_yticks(range(bandwidth.shape[0]))  # Number of rows in bandwidth
                    ax.set_yticklabels([f"Row {i+1}" for i in range(bandwidth.shape[0])])

                    # Align Y-axis tick labels horizontally
                    for tick in ax.get_yticklabels():
                        tick.set_rotation(0)  # Ensure horizontal alignment

                    # Set title for the heatmap
                    ax.set_title("Bandwidth Heatmap")

                    # Draw the canvas to render the heatmap
                    canvas.draw()

                    # Update layout in widget_4
                    if self.ui.widget_4.layout() is None:
                        layout = QVBoxLayout(self.ui.widget_4)
                        self.ui.widget_4.setLayout(layout)
                    else:
                        layout = self.ui.widget_4.layout()
                        while layout.count():
                            child = layout.takeAt(0)
                            if child.widget():
                                child.widget().deleteLater()

                    layout.addWidget(canvas)

            if self.ui.comboBox_5.currentText() == "Protocols":
                
                    # Access packet statistics from the main window
                packet_stats = self.main_window.PacketSystemobj.packets  # Replace with your actual packet stats
            
                # Define the protocols
                protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "Telnet", "DNS", "DHCP", "Other"]
                
                # Validate packet data
                if not packet_stats:
                    raise ValueError("No packets available for analysis.")
                
                # Get the times of the packets (as datetime objects)
                packet_times = [datetime.fromtimestamp(packet.time) for packet in packet_stats if hasattr(packet, 'time')]
                if not packet_times:
                    raise ValueError("No valid timestamps in packets.")
                
                # Define the time range for the graph (start and end time)
                start_time = min(packet_times)
                end_time = max(packet_times)

                # Generate intervals based on the packet timestamps
                interval_count = 10  # Adjust this for more or fewer intervals
                intervals = np.linspace(start_time.timestamp(), end_time.timestamp(), interval_count + 1)  # Convert to timestamp
                
                # Initialize the heatmap data (list of lists with zeros)
                heatmap_data = np.zeros((interval_count, len(protocols)))
                
                # Count packets for each protocol in each time interval
                for packet in packet_stats:
                    packet_time = getattr(packet, 'time', None)
                    packet_protocol = getattr(packet, 'protocol', 'Other')
                    
                    if packet_time is not None:
                        packet_time = datetime.fromtimestamp(packet_time).timestamp()  # Convert to timestamp
                        for i in range(interval_count):
                            if intervals[i] <= packet_time < intervals[i + 1]:  # Compare using timestamps
                                protocol_index = protocols.index(packet_protocol) if packet_protocol in protocols else len(protocols) - 1  # 'Other' protocol index
                                heatmap_data[i][protocol_index] += 1
                                break  # Stop once we find the interval for the packet

                # Create the heatmap
                figure = plt.Figure(figsize=(6, 4))
                canvas = FigureCanvas(figure)
                ax = figure.add_subplot(111)
                cax = ax.matshow(heatmap_data, cmap='coolwarm')
                
                # Add colorbar
                figure.colorbar(cax)
                
                # Format the time intervals as strings for the x-axis labels
                time_interval_labels = [datetime.fromtimestamp(interval).strftime("%I:%M:%S %p") for interval in intervals[:-1]]
                
                # Set the tick labels for time intervals and protocols
                ax.set_xticks(range(len(time_interval_labels)))
                ax.set_yticks(range(len(protocols)))
                ax.set_xticklabels(time_interval_labels, rotation=45, ha='right')  # Rotate for better readability
                ax.set_yticklabels(protocols)
                
                # Set the title
                ax.set_title("Protocol Heatmap Over Time")
                
                canvas.draw()

                # Clear the previous canvas in widget_4
                if self.ui.widget_4.layout() is None:
                    layout = QVBoxLayout(self.ui.widget_4)
                    self.ui.widget_4.setLayout(layout)
                else:
                    layout = self.ui.widget_4.layout()
                    # Clear the previous widgets in the layout
                    for i in range(layout.count()):
                        child = layout.itemAt(i).widget()
                        if child is not None:
                            child.deleteLater()

                layout.addWidget(canvas)

    def display_pie_chart(self):
        """Display the pie chart based on the selected option."""
        if self.selected_option=="inside/outside":

            total_inisde=self.main_window.PacketSystemobj.total_inside_packets
            total_outside=self.main_window.PacketSystemobj.total_outside_packets
            labels=["inside","Outside"]
            sizes=[]
            sizes.append(total_inisde)
            sizes.append(total_outside)
            colors = ['#ff9999', '#66b3ff']
            print(f"Sizes: {sizes}, Labels: {labels}")
            figure = Figure(figsize=(4, 4), facecolor='white')
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            wedges, texts, autotexts = ax.pie(
                sizes, 
                autopct='%1.1f%%', 
                startangle=140, 
                colors=colors
            )

            # Add a legend outside the pie chart
            ax.legend(
                wedges, 
                labels, 
                loc="center left", 
                bbox_to_anchor=(1, 0.5), 
                title="Inside/Outside"
            )

            # Set the title
            ax.set_title("Inside/Outside Proportions")

            # Adjust layout to fit the legend
            figure.tight_layout()
            canvas.draw()
            canvas.setParent(self.ui.widget)  # Set parent to self.ui.widget
            canvas.setGeometry(0, 0, self.ui.widget.width(), self.ui.widget.height())  # Adjust canvas size
            canvas.show()
        #end of if for inside/outside
       
        if self.selected_option == "Protocols":
            # Access packet stats
      
            packet_stats = self.main_window.PacketSystemobj.packet_stats
           

            # Extract data for the pie chart
            tcp_count = packet_stats.get("tcp", 0)
            udp_count = packet_stats.get("udp", 0)
            icmp_count = packet_stats.get("icmp", 0)
            total_count = packet_stats.get("total", 0)
            other_count = total_count - (tcp_count + udp_count + icmp_count)

            # Prepare data for the pie chart
            labels = ["  TCP  ", "    UDP    ", "   ICMP   ", "  Other   "]
            sizes = [tcp_count, udp_count, icmp_count, other_count]
            colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']

            print(f"Sizes: {sizes}, Labels: {labels}")
            figure = Figure(figsize=(4, 4), facecolor='white')
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            wedges, texts, autotexts = ax.pie(
                sizes, 
                autopct='%1.1f%%', 
                startangle=140, 
                colors=colors
            )

            # Add a legend outside the pie chart
            ax.legend(
                wedges, 
                labels, 
                loc="center left", 
                bbox_to_anchor=(1, 0.5), 
                title="Protocols"
            )

            # Set the title
            ax.set_title("Protocol Proportions")

            # Adjust layout to fit the legend
            figure.tight_layout()
            canvas.draw()

            # Clear existing children in the widget
           

            # Embed the canvas into the widget
            canvas.setParent(self.ui.widget)  # Set parent to self.ui.widget
            canvas.setGeometry(0, 0, self.ui.widget.width(), self.ui.widget.height())  # Adjust canvas size
            canvas.show()
        #end of protocol if pie charyt
        if self.selected_option == "Sensors":
             # Access packet stats
           
            sensors = self.main_window.SensorSystemobj.sen_info
          
            sizes=[]
            labels=[]
            for s in range(0,len(self.main_window.SensorSystemobj.sen_info)-1,2):
                labels.append(sensors[s])
                sizes.append(sensors[s+1])
               

        
            colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']

            print(f"Sizes: {sizes}, Labels: {labels}")
            figure = Figure(figsize=(4, 4), facecolor='white')
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            wedges, texts, autotexts = ax.pie(
                sizes, 
                autopct='%1.1f%%', 
                startangle=140, 
                colors=colors
            )

            # Add a legend outside the pie chart
            ax.legend(
                wedges, 
                labels, 
                loc="center left", 
                bbox_to_anchor=(1, 0.5), 
                title="sensors"
            )

            # Set the title
            ax.set_title("sensors Proportions")

            # Adjust layout to fit the legend
            figure.tight_layout()
            canvas.draw()

           

            # Embed the canvas into the widget
            canvas.setParent(self.ui.widget)  # Set parent to self.ui.widget
            canvas.setGeometry(0, 0, self.ui.widget.width(), self.ui.widget.height())  # Adjust canvas size
            canvas.show()
        #end of sensorrs

        #end of pie chart
    def show_main_window(self):
        """Show the main window and hide this widget."""
        self.main_window.show()
        self.hide()



if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = Window_Analysis()
    main_window.show()
    sys.exit(app.exec())
