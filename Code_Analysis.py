import sys
import numpy as np
import threading
import plotly.graph_objects as go
import geoip2.database
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import QPixmap
from scapy.layers.inet import IP
from scapy.all import *
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from UI_Analysis import Ui_Naswail_Anlaysis
from Code_Tools import Window_Tools
from Code_IncidentResponse import IncidentResponse

class GeoMap(threading.Thread):
    def __init__(self, ui, packets, anomalies):
        super().__init__()
        self.ui = ui
        self.packets = packets
        self.anomalies = anomalies
        self.geoip_db_path = "GeoLite2-City.mmdb"
        self.lastindex = 0
        self.src_lats, self.src_lons = [], []
        self.dst_lats, self.dst_lons = [], []
        self.lines = []
        self.start()  

    def get_location(self, ip):
        try:
            with geoip2.database.Reader(self.geoip_db_path) as reader:
                response = reader.city(ip)
                lat = response.location.latitude
                lon = response.location.longitude
                return lat, lon
        except geoip2.errors.AddressNotFoundError:
            return 30.0444, 31.2357

    def create_map(self):
        try:
            
            for i in range(self.lastindex, len(self.packets)):
                if IP in self.packets[i]:
                    
                    src_lat, src_lon = self.get_location(self.packets[i][IP].src)
                    dst_lat, dst_lon = self.get_location(self.packets[i][IP].dst)

                    # Only process if coordinates are valid
                    if None not in (src_lat, src_lon, dst_lat, dst_lon) and (src_lat, src_lon) != (0, 0) and (dst_lat, dst_lon) != (0, 0):
                        self.src_lats.append(src_lat)
                        self.src_lons.append(src_lon)
                        self.dst_lats.append(dst_lat)
                        self.dst_lons.append(dst_lon)

                        

                        # add lines connecting the source to destination
                        if self.packets[i] in self.anomalies:
                            self.lines.append({
                                "type": "scattergeo",
                                "lat": [src_lat, dst_lat],
                                "lon": [src_lon, dst_lon],
                                "mode": "lines",
                                "line": {"width": 1, "color": "red"},
                            })
                        else:
                            self.lines.append({
                                "type": "scattergeo",
                                "lat": [src_lat, dst_lat],
                                "lon": [src_lon, dst_lon],
                                "mode": "lines",
                                "line": {"width": 1, "color": "green"},
                            })

            self.lastindex = len(self.packets)

            points = go.Scattergeo(
                lon=self.src_lons + self.dst_lons,  # Combine source and destination lon values
                lat=self.src_lats + self.dst_lats,  # Combine source and destination lat values
                mode="markers",
                marker=dict(size=6, color="blue"),
                text=[f"Source: {p[IP].src}" for p in self.packets if IP in p] + [f"Destination: {p[IP].dst}" for p in self.packets if IP in p],
            )

            # Combine points and lines
            fig = go.Figure(data=[points] + self.lines)

            # Set map layout
            fig.update_layout(
                title="Packet Origins and Destinations",
                geo=dict(
                    scope="world",
                    projection_type="equirectangular",
                    showland=True,
                    landcolor="rgb(243, 243, 243)",
                    subunitcolor="rgb(217, 217, 217)",
                ),
            )

            
            image_path = "packet_map.png"
            fig.write_image(image_path)  
            pixmap = QPixmap(image_path)
            self.ui.label.setPixmap(pixmap)

        except Exception as e:
            print(f"Error in create_map function: {e}")
    
    def run(self):
        print("GeoMap Thread is running...")
        self.create_map()


class Node:
    def __init__(self):
        self.mac_address = ""
        self.edges = set()  # set of connected devices


class NetworkTopologyVisualizer(threading.Thread):
    def __init__(self,packetobj, ui):
        super().__init__()
        self.ui = ui
        self.list_of_nodes = []
        self.packetobj=packetobj
        # Layout for self.ui.widget_6
        self.layout = QVBoxLayout(self.ui.widget_6)

        
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas)

        self.start()

    def find_unique_devices_and_edges(self):
        try:
            unique_ips = set()
            pure_local=[]#local in both dst and src
            #  unique IP addresses
            for packet in self.packetobj.qued_packets:
                src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                islocal=self.packetobj.is_local_ip(dst_ip)
                islocal2=self.packetobj.is_local_ip(src_ip)
                if "255" in src_ip or "255" in dst_ip:
                    continue

                if islocal:
                    unique_ips.add(dst_ip)
                
                if islocal2:
                    unique_ips.add(src_ip)
                if islocal2 and islocal:
                    pure_local.append(packet) 
           
            
            # Create nodes
            for ip in unique_ips:
                new_node = Node()
                new_node.mac_address = ip
                self.list_of_nodes.append(new_node)
            
            
            # connections
            for current_node in self.list_of_nodes:
                for packet in pure_local:
                    
                    dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
                    src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
                    if dst_ip == current_node.mac_address:
                        current_node.edges.add(src_ip)
                    if src_ip == current_node.mac_address:
                        current_node.edges.add(dst_ip)
            
            
        except Exception as e:
            print(f"Error in unique IP function: {e}")

    
    def visualize_network(self):
        # Create a graph
        G = nx.Graph()

        # Add nodes and edges to the graph
        pos = {}  # Dictionary to store node positions
        for i, node in enumerate(self.list_of_nodes):
            G.add_node(node.mac_address)
            # semi random pos
            pos[node.mac_address] = (i, i % 2, i // 2)

            # Add edges based on connections
            for connected_mac in node.edges:
                G.add_edge(node.mac_address, connected_mac)

        # Create a 3D 
        ax = self.figure.add_subplot(111, projection='3d')
        self.figure.patch.set_alpha(0.0)  
        ax.set_facecolor((0, 0, 0, 0))  

        # Draw the edges
        for edge in G.edges():
            x = [pos[edge[0]][0], pos[edge[1]][0]]
            y = [pos[edge[0]][1], pos[edge[1]][1]]
            z = [pos[edge[0]][2], pos[edge[1]][2]]
            ax.plot(x, y, z, color='black')

        # Draw the nodes
        i=1
        for mac_address, (x, y, z) in pos.items():
            lab = "device "+i.__str__()+":  "+mac_address
            i+=1
            for name,mac in self.packetobj.sensor_obj.sensors.items():
                if mac == mac_address:
                    lab = name+": "+mac  
                    break  
            ax.scatter(x, y, z, s=100, label=lab)

        # Set labels
        ax.set_xlabel('X')
        ax.set_ylabel('Y')
        ax.set_zlabel('Z')

        # Display legend if nodes exist
        if self.list_of_nodes:
             ax.legend(
        
        bbox_to_anchor=(1.45, 1.05),  # Move the legend to the right and slightly higher
        borderaxespad=0.0  # Padding between the legend and the axes
    )

        
        self.canvas.draw()
        plt.close()

    def run(self):
        print("3D Thread is running...")
        self.find_unique_devices_and_edges()
        self.visualize_network()

class visualization:#class for all the charts
    def __init__(self,main_window,ui):
        self.main_window=main_window
        self.ui=ui
        self.selected_option = "Protocols"
   
    def display_all(self):
        self.display_pie_chart()
        self.display_histogram()
        self.display_graph()
        self.display_heatmap()
        self.display_time_series()
    def display_histogram(self):
        try:
            
            if self.ui.comboBox_3.currentText()=="inside/outside":
                total_inside=self.main_window.PacketSystemobj.total_inside_packets
                total_outside=self.main_window.PacketSystemobj.total_outside_packets
                labels=["Inside","Outside"]
                counts = [total_inside, total_outside]
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
                
                packet_stats = self.main_window.PacketSystemobj.packet_stats

                
                protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "Telnet", "DNS", "DHCP", "Other"]

                
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
                    packet_stats.get("other",0)
                    
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
        except Exception as e:
            print(f"Error in display_histogram function: {e}")
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
        try:
 
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
                
                    sensors = self.main_window.SensorSystemobj.sen_info

                   
                    packet_stats = self.main_window.PacketSystemobj.packets 
                    packet_times = [packet.time for packet in packet_stats]

                
                    start_time = min(packet_times)
                    end_time = max(packet_times)

                
                    intervals = np.linspace(start_time, end_time, 11)  # 11 because we want 10 intervals

                    # I list to hold the packet counts for each interval (for 10 intervals)
                    packet_counts = [0] * 10

                    # Count how many packets fall into each time interval
                    for packet_time in packet_times:
                        for i in range(10):
                            if intervals[i] <= packet_time < intervals[i + 1]:
                                packet_counts[i] += 1
                                break  # Stop once we find the interval for the packet

                
                    figure = plt.Figure(figsize=(6, 4))  
                    canvas = FigureCanvas(figure)
                    ax = figure.add_subplot(111)

                
                    time_labels = [datetime.fromtimestamp(interval).strftime("%I:%M:%S %p") for interval in intervals[:-1]]

                   
                    ax.plot(intervals[:-1], packet_counts, label='sensor Packet Counts', marker='o')

                    # Set labels and title
                    ax.set_xlabel("Time interval")
                    ax.set_ylabel("sensor Packet Count")
                    ax.set_title("sensor Packet Counts Over Time")

                    # Set x-axis ticks and labels
                    ax.set_xticks(intervals[:-1])
                    ax.set_xticklabels(time_labels, rotation=45, ha="right")  

                    # Increase bottom margin for x-axis labels
                    figure.subplots_adjust(bottom=0.2)

                    # Add legend
                    ax.legend()
                    
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
                        
                                
                    packet_stats = self.main_window.PacketSystemobj.packets  

                    
                    packet_times = [packet.time for packet in packet_stats]

                    
                    start_time = min(packet_times)
                    end_time = max(packet_times)

                    
                    intervals = np.linspace(start_time, end_time, 11)  # 11 because we want 10 intervals

                    #  a list to hold the packet counts for each interval
                    packet_counts = [0] * 10

                    
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
        except Exception as e:
            print(f"An error occurred: {e}")


    def display_heatmap(self):
            try:
                """Display a heatmap based on the selected option."""
                if self.ui.comboBox_5.currentText() == "Bandwidth":
                    bandwidth_data = self.main_window.PacketSystemobj.bandwidth_data
                    if bandwidth_data:
                        
                        times, bandwidth = zip(*bandwidth_data)
                        bandwidth = np.array(bandwidth)  # Convert bandwidth to numpy array
                        
                        bandwidth = bandwidth.reshape(1, -1)  # Reshape into 2D array (1 row, n columns)
                        # Optional: Add more rows for better visualization
                        bandwidth = np.tile(bandwidth, (5, 1))  #  5 times for better visual effect
                        
                        # Create the figure and canvas
                        figure = Figure(figsize=(4, 4))  # Larger figure size for better readability
                        canvas = FigureCanvas(figure)
                        ax = figure.add_subplot(111)
                        
                        # Plot the heatmap
                        cax = ax.matshow(bandwidth, cmap='coolwarm', aspect='auto')  # 'aspect=auto' for better scaling
                        
                        # Add colorbar for the heatmap
                        figure.colorbar(cax)
                        
                        # Set tick labels for time (X-axis)
                        ax.set_xticks(range(len(times)))
                        
                    
                        label_step = max(1, len(times) // 10)  # Show at most 10 time labels
                        ax.set_xticks(range(0, len(times), label_step))
                        
                        # Use only every nth time interval label
                        ax.set_xticklabels(times[::label_step], rotation=45, ha='right')  # Rotate for readability
                        
                        # Set tick labels for Y-axis (Bandwidth rows)
                        ax.set_yticks(range(bandwidth.shape[0]))  # Number of rows in bandwidth
                        row_sums = np.sum(bandwidth, axis=1)  # Sum each row to get the total bandwidth for that row
                        ax.set_yticklabels([f" {int(row_sum)}" for row_sum in row_sums])  # D
                        
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
                if self.ui.comboBox_5.currentText() == "Sensors":

                    sensors = self.main_window.SensorSystemobj.sen_info

                    counts = []
                    labels = []
                    for s in range(0, len(self.main_window.SensorSystemobj.sen_info) - 1, 2):
                        labels.append(sensors[s])
                        counts.append(sensors[s + 1])
                    counts = np.array(counts).reshape(1, -1)  # Reshape into a 2D array (1 row, n columns)
                        
                    # Create the figure and canvas
                    figure = Figure(figsize=(2, 2))  # Larger figure size for better readability
                    canvas = FigureCanvas(figure)
                    ax = figure.add_subplot(111)
                    
                    # Plot the heatmap
                    cax = ax.matshow(counts, cmap='coolwarm', aspect='auto')  # 'aspect=auto' for better scaling
                    
                    # Add colorbar for the heatmap
                    figure.colorbar(cax)
                    
                    # Set tick labels for the x-axis (sensor names)
                    ax.set_xticks(range(len(labels)))
                    ax.set_xticklabels(labels, rotation=45, ha='right')  # Rotate for readability
                    
                    # Set tick labels for the y-axis (since it's just one row, we'll show "Packets")
                    ax.set_yticks([0])  # Only one row in the heatmap
                    ax.set_yticklabels(["Sensor Packet Counts"])
                    
                    # Set title for the heatmap
                    ax.set_title("Sensor Packet Count Heatmap")
                    
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
            except Exception as e:
                print(f"Error: {e}")

    def display_pie_chart(self):
        try:
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
                other_count = packet_stats.get("other",0)
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
        except Exception as e:        
            print(f"Error: {e}")
        #end of pie chart


class Window_Analysis(QWidget, Ui_Naswail_Anlaysis):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window  # Reference to the main window

        self.ui = Ui_Naswail_Anlaysis()  # Create an instance of the UI class
        self.ui.setupUi(self)  # Set up the UI for this widget
        self.init_ui()
        self.Visualizationobj=visualization(self.main_window,self.ui)
        self.ThreeDVisulizationobj=NetworkTopologyVisualizer(self.main_window.PacketSystemobj,self.ui)
        self.GeoMapObj = GeoMap(self.ui, self.main_window.PacketSystemobj.packets, self.main_window.PacketSystemobj.anomalies)
        #self.GeoMapObj.start()
    def init_ui(self):
        self.setWindowTitle("Secondary Widget")
        self.showMaximized()
        self.setWindowTitle("Naswail - Visualization")
        self.Visualizationobj=visualization(self.main_window,self.ui)
        # Connect comboBox_2 selection change
        self.ui.comboBox_2.currentIndexChanged.connect(self.on_combobox_change)
        self.ui.comboBox_3.currentIndexChanged.connect(self.on_combobox_change)
        self.ui.comboBox_4.currentIndexChanged.connect(self.on_combobox_change)
        self.ui.comboBox_5.currentIndexChanged.connect(self.on_combobox_change)
        self.ui.comboBox_6.currentIndexChanged.connect(self.on_combobox_change)
        # Connect PushButton_5 click to display pie chart
        
        pixmap = QPixmap(r"logo.png")
        self.pixmap_item = QGraphicsPixmapItem(pixmap)
        self.scene = QGraphicsScene(self)
        self.scene.addItem(self.pixmap_item)
        self.ui.graphicsView.setScene(self.scene)
        self.ui.graphicsView.setFixedSize(71, 61)
        self.ui.graphicsView.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self.ui.pushButton_4.clicked.connect(self.show_main_window)
        self.ui.pushButton_3.clicked.connect(self.show_tools_window)
        self.ui.pushButton_5.clicked.connect(self.show_incidentresponse_window)

        self.ui.label.setText("")
       
     
        # Initialize a placeholder for selected option
        self.selected_option = "Protocols"
        self.Visualizationobj.display_graph()
        self.Visualizationobj.display_heatmap()
        self.Visualizationobj.display_histogram()
        self.Visualizationobj.display_pie_chart()
        self.Visualizationobj.display_time_series()

    def on_combobox_change(self):
        """Handle changes in comboBox_2."""
        self.selected_option = self.ui.comboBox_2.currentText()
        self.Visualizationobj.selected_option = self.selected_option
        self.Visualizationobj.display_all()
        print(f"Selected option: {self.selected_option}")  # Debugging output
    def show_main_window(self):
        """Show the main window and hide this widget."""
        self.main_window.show()
        self.hide()
    def show_tools_window(self):
        """Show the tools window and hide this widget."""
        self.secondary_widget2 = Window_Tools(self.main_window)
        self.hide()
        self.secondary_widget2.show()
    def show_incidentresponse_window(self):
        """Show the tools window and hide this widget."""
        self.secondary_widget2 = IncidentResponse(self.main_window)
        self.hide()
        self.secondary_widget2.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = Window_Analysis()
    main_window.show()
    sys.exit(app.exec())
