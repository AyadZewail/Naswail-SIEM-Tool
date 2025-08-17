import sys
import numpy as np
import threading
from PyQt6.QtCore import pyqtSignal, pyqtSlot, QObject

# Set matplotlib backend before importing pyplot
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend

import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas

import plotly.graph_objects as go
import geoip2.database
import networkx as nx
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import QPixmap, QPainter, QColor, QPen, QBrush, QFont, QPainterPath, QImage
from scapy.layers.inet import IP
from scapy.all import *
from views.UI_Analysis import Ui_Naswail_Anlaysis
from Code_Tools import Window_Tools
from Code_IncidentResponse import IncidentResponse
import math
from models.node import Node
from core import di
from plugins.analysis.GeoMapper import MaxMindGeoMapper

class GeoMap(threading.Thread, QObject):
    # Define signal to send pixmap to the main thread
    pixmapReady = pyqtSignal(QPixmap)
    
    # Class variables for real location
    real_location_fetched = False
    real_lat = 30.0444
    real_lon = 31.2357
    real_location_name = "Cairo (Default)"
    
    def __init__(self, geo_mapper, packets, anomalies):
        threading.Thread.__init__(self)
        QObject.__init__(self)
        self.ui = None
        self.packets = packets
        self.anomalies = anomalies
        self.geoip_db_path = "resources/GeoLite2-City.mmdb"
        self.lastindex = 0
        self.src_lats, self.src_lons = [], []
        self.dst_lats, self.dst_lons = [], []
        self.lines = []
        self.geoMapper = MaxMindGeoMapper(self.geoip_db_path)
        
        # Connect signal to label update function
        self.pixmapReady.connect(self.update_ui_label)
        
        try:
            lat, lon, name = self.geoMapper.get_real_location()
            GeoMap.real_lat = lat
            GeoMap.real_lon = lon
            GeoMap.real_location_name = name
            GeoMap.real_location_fetched = True
        except Exception:
            pass
        
        # Move to daemon thread for automatic cleanup
        self.daemon = True 

    def set_ui(self, ui):
        self.ui = ui
        self.start() 
    
    def get_location(self, ip):
        try:
            lat, lon = self.geoMapper.get_location(ip)
            return lat, lon
        except geoip2.errors.AddressNotFoundError:
            # Use the pre-fetched real location
            return GeoMap.real_lat, GeoMap.real_lon
        except Exception as e:
            print(f"Error getting location for IP {ip}: {e}")
            return GeoMap.real_lat, GeoMap.real_lon  # Use real location as fallback
    
    @pyqtSlot(QPixmap)
    def update_ui_label(self, pixmap):
        """This method runs in the main thread to update the UI safely"""
        try:
            if not pixmap.isNull():# and self.ui and hasattr(self.ui, 'label') and self.ui.label is not None:
                print("Updating UI label with pixmap from main thread")
                self.ui.label.setPixmap(pixmap)
                self.ui.label.setScaledContents(True)
            else:
                print("Pixmap was null or UI label is not available")
        except RuntimeError as e:
            print(f"UI update error: {e}")  # This catches the C++ object deleted error
        except Exception as e:
            print(f"Unexpected error updating UI: {e}")

    def create_map(self):
        try:
            print("Starting create_map function...")
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
                                "line": {"width": 1, "color": "blue"},
                            })

            self.lastindex = len(self.packets)

            print(f"Processing {len(self.src_lats)} data points for the map...")
            if len(self.src_lats) == 0:
                print("No valid coordinates found for the map")
                return
            
            # Create a basic plot without a map
            print("Creating map visualization with world map background...")
            # Create a direct rendering using QPainter
            from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QPainterPath, QImage
            from PyQt6.QtCore import Qt, QPointF, QRect
            import os
            
            # Create a new QPixmap with appropriate size
            pixmap_width, pixmap_height = 700, 450
            
            # Load the world map background
            world_map_path = "resources/newworldmap.png"  # Try the equirectangular map first
            if not os.path.exists(world_map_path):
                world_map_path = "resources/worldmap.png"  # Fall back to original map
            
            # Check if world map exists
            if not os.path.exists(world_map_path):
                print(f"World map file not found. Using plain background.")
                pixmap = QPixmap(pixmap_width, pixmap_height)
                pixmap.fill(QColor('#1a1a2e'))  # Dark blue background
            else:
                try:
                    # Load the world map as background and convert to grayscale
                    from PyQt6.QtGui import QImage
                    print(f"Converting world map to grayscale...")
                    
                    # Load the image
                    background_image = QImage(world_map_path)
                    
                    # Convert to grayscale
                    for y in range(background_image.height()):
                        for x in range(background_image.width()):
                            pixel_color = background_image.pixelColor(x, y)
                            # Calculate grayscale value but make it lighter
                            gray_value = int(0.299 * pixel_color.red() + 0.587 * pixel_color.green() + 0.114 * pixel_color.blue())
                            # Make it lighter by adding an offset (clamp to 255 max)
                            gray_value = min(255, gray_value + 40)
                            pixel_color.setRgb(gray_value, gray_value, gray_value)
                            background_image.setPixelColor(x, y, pixel_color)
                    
                    background_map = QPixmap.fromImage(background_image)
                    pixmap = QPixmap(pixmap_width, pixmap_height)
                    
                    # Scale the background map to fit our pixmap size
                    scaled_map = background_map.scaled(pixmap_width, pixmap_height, 
                                                    Qt.AspectRatioMode.IgnoreAspectRatio, 
                                                    Qt.TransformationMode.SmoothTransformation)
                    
                    # Create a slightly transparent version of the map for better data visibility
                    pixmap.fill(Qt.GlobalColor.transparent)
                    painter = QPainter(pixmap)
                    painter.setOpacity(0.8)  # Make the map slightly transparent
                    painter.drawPixmap(0, 0, scaled_map)
                    painter.setOpacity(1.0)  # Reset opacity for data points
                except Exception as e:
                    print(f"Error processing world map: {e}")
                    pixmap = QPixmap(pixmap_width, pixmap_height)
                    pixmap.fill(QColor('#1a1a2e'))  # Dark blue background if error occurs
            
            # Start painting
            if not os.path.exists(world_map_path):
                # If we didn't load a background, we need to initialize the painter
                painter = QPainter(pixmap)
                
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            
            # Convert lat/lon to x,y coordinates
            def latlon_to_xy(lat, lon):
                # Simple conversion from lat/lon to x,y in pixmap
                # Make sure longitude is correctly handled for the map
                # Most world maps have longitude ranging from -180 to +180
                # with 0 at the center (Greenwich meridian)
                
                # X coordinate: Convert longitude from -180...+180 to 0...pixmap_width
                x = ((lon + 180) / 360) * pixmap_width
                
                # Y coordinate: Convert latitude from +90 (North Pole) to -90 (South Pole)
                # to 0...pixmap_height, leaving room for title and legend
                y = ((90 - lat) / 180) * (pixmap_height - 60) + 30
                
                # Debug output for Cairo coordinates
                if abs(lat - 30.0444) < 0.001 and abs(lon - 31.2357) < 0.001:
                    print(f"Cairo coordinates: lat={lat}, lon={lon} -> x={x}, y={y}")
                    # Cairo is at ~30° North, ~31° East
                    # Should be slightly above the equator and slightly east of Greenwich
                
                return x, y
            
            # Draw connections as curved lines
            for i in range(len(self.src_lats)):
                x1, y1 = latlon_to_xy(self.src_lats[i], self.src_lons[i])
                x2, y2 = latlon_to_xy(self.dst_lats[i], self.dst_lons[i])
                
                # Check if this packet is an anomaly and set the color accordingly
                if i < len(self.packets) and self.packets[i] in self.anomalies:
                    # Red color for anomalies
                    painter.setPen(QPen(QColor(255, 0, 0, 255), 1.5))  # Pure red line for anomalies
                    # Slightly increase curve height for anomalies
                    anomaly_factor = 1.20  # Just 10% more curved
                else:
                    # Blue color for regular connections
                    painter.setPen(QPen(QColor(0, 0, 255, 255), 1.5))  # Pure blue line for normal connections
                    anomaly_factor = 1.0  # Normal curvature
                
                # Create curved path
                path = QPainterPath()
                path.moveTo(x1, y1)
                
                # Calculate control points for bezier curve
                # The curve height is proportional to the distance between points
                dx = x2 - x1
                dy = y2 - y1
                dist = (dx**2 + dy**2)**0.5  # Distance between points
                
                # Determine curve height (bulge)
                curve_height = min(dist / 3, 150) * anomaly_factor  # Cap at 150px to avoid extreme curves, apply anomaly factor
                
                # Calculate control point - perpendicular to the line
                # This creates a nice arc effect
                mid_x = (x1 + x2) / 2
                mid_y = (y1 + y2) / 2
                
                # For points on opposite sides of the map
                if abs(dx) > pixmap_width / 2:
                    # Skip drawing these lines that would wrap around the world
                    continue
                
                # Calculate perpendicular vector to create curve
                if dx == 0:  # Vertical line case
                    ctrl_x = mid_x + curve_height
                    ctrl_y = mid_y
                else:
                    # Perpendicular slope is negative reciprocal
                    slope = -dx / dy if dy != 0 else 0
                    angle = math.atan(slope)
                    
                    # Always make curves bend upward (negative y direction)
                    # Flip the sign if needed based on the line direction
                    side = -1  # Start with upward (-1 in screen coordinates)

                    # If the line is mostly horizontal, we need to adjust the side
                    # to make sure it points upward relative to the screen
                    if abs(dx) > abs(dy):  # More horizontal than vertical
                        if slope > 0:  # Line goes down-right or up-left
                            side = -1  # Keep upward
                        else:  # Line goes up-right or down-left
                            side = 1   # Switch to make it visually upward
                    
                    ctrl_x = mid_x + side * curve_height * math.cos(angle)
                    ctrl_y = mid_y + side * curve_height * math.sin(angle)
                    
                    # Force curves to always go upward in screen coordinates (smaller y)
                    if ctrl_y > mid_y:  # If control point is below midpoint (larger y value)
                        side *= -1  # Flip the side to make it go upward
                        ctrl_x = mid_x + side * curve_height * math.cos(angle)
                        ctrl_y = mid_y + side * curve_height * math.sin(angle)
                
                # Add the quadratic bezier curve
                path.quadTo(ctrl_x, ctrl_y, x2, y2)
                painter.drawPath(path)
                
                # Add arrow at destination for direction
                arrow_size = 6  # Smaller arrow
                # Calculate angle of arrival
                angle = math.atan2(y2 - ctrl_y, x2 - ctrl_x)
                # Draw arrow
                arrow_p1 = QPointF(x2 - arrow_size * math.cos(angle - math.pi/6), 
                                 y2 - arrow_size * math.sin(angle - math.pi/6))
                arrow_p2 = QPointF(x2 - arrow_size * math.cos(angle + math.pi/6), 
                                 y2 - arrow_size * math.sin(angle + math.pi/6))
                painter.drawLine(QPointF(x2, y2), arrow_p1)
                painter.drawLine(QPointF(x2, y2), arrow_p2)
            
            # Draw all network nodes as a single type (no distinction between source and destination)
            painter.setPen(QPen(Qt.GlobalColor.white, 1))  # White outline
            painter.setBrush(QBrush(QColor(0, 255, 0, 255)))  # Pure green with full opacity
            
            # Create a set of all unique node coordinates to avoid drawing duplicates
            unique_nodes = set()
            
            # Process all source and destination nodes
            for i in range(len(self.src_lats)):
                # Add source coordinates
                src_coords = (self.src_lats[i], self.src_lons[i])
                if src_coords not in unique_nodes:
                    unique_nodes.add(src_coords)
                
                # Add destination coordinates
                dst_coords = (self.dst_lats[i], self.dst_lons[i])
                if dst_coords not in unique_nodes:
                    unique_nodes.add(dst_coords)
            
            # Draw all unique nodes
            for lat, lon in unique_nodes:
                x, y = latlon_to_xy(lat, lon)
                painter.drawEllipse(QPointF(x, y), 4, 4)  # Draw nodes with consistent size
            
            # Create a semi-transparent background for legend
            legend_rect = QRect(10, pixmap_height - 80, 300, 60)  # Wider and shorter legend
            painter.setBrush(QBrush(QColor(30, 30, 30, 180)))  # Semi-transparent dark background
            painter.setPen(QPen(QColor(200, 200, 200, 150), 1))
            painter.drawRoundedRect(legend_rect, 10, 10)
            
            # Draw legend
            legend_font = QFont()
            legend_font.setPointSize(9)  # Slightly smaller font
            painter.setFont(legend_font)
            
            # Network node legend
            painter.setPen(QColor('#FFFFFF'))  # White color for text
            painter.drawText(20, pixmap_height - 60, "Network Node")
            painter.setPen(QPen(Qt.GlobalColor.white, 1))
            painter.setBrush(QBrush(QColor(0, 255, 0, 255)))  # Pure green to match nodes
            painter.drawEllipse(QPointF(105, pixmap_height - 60), 4, 4)
            
            # Normal connection legend
            painter.setPen(QColor('#FFFFFF'))  # White color for text
            painter.drawText(130, pixmap_height - 60, "Normal Traffic")
            painter.setPen(QPen(QColor(0, 0, 255, 255), 1.5))  # Pure blue lines
            
            # Draw a small curved line for normal connections in the legend
            legend_x1 = 210
            legend_y1 = pixmap_height - 60
            legend_x2 = 240
            legend_y2 = pixmap_height - 60
            
            # Normal connection curved path
            legend_path = QPainterPath()
            legend_path.moveTo(legend_x1, legend_y1)
            legend_path.quadTo(
                (legend_x1 + legend_x2) / 2,  # control point x 
                legend_y1 - 10,              # control point y (curved up)
                legend_x2, 
                legend_y2
            )
            painter.drawPath(legend_path)
            
            # Anomaly connection legend
            painter.setPen(QColor('#FFFFFF'))  # White color for text
            painter.drawText(20, pixmap_height - 35, "Anomaly")
            painter.setPen(QPen(QColor(255, 0, 0, 255), 1.5))  # Pure red lines
            
            # Draw a small curved line for anomaly connections in the legend
            legend_x1_anom = 80
            legend_y1_anom = pixmap_height - 35
            legend_x2_anom = 110
            legend_y2_anom = pixmap_height - 35
            
            # Anomaly connection curved path
            legend_path_anom = QPainterPath()
            legend_path_anom.moveTo(legend_x1_anom, legend_y1_anom)
            legend_path_anom.quadTo(
                (legend_x1_anom + legend_x2_anom) / 2,  # control point x 
                legend_y1_anom - 10,              # control point y (curved up)
                legend_x2_anom, 
                legend_y2_anom
            )
            painter.drawPath(legend_path_anom)
            
            # Add arrows to legend lines
            arrow_size = 4
            # Normal traffic arrow
            painter.setPen(QPen(QColor(0, 0, 255, 255), 1.5))
            painter.drawLine(
                QPointF(legend_x2, legend_y2),
                QPointF(legend_x2 - arrow_size, legend_y2 - arrow_size/2)
            )
            painter.drawLine(
                QPointF(legend_x2, legend_y2),
                QPointF(legend_x2 - arrow_size, legend_y2 + arrow_size/2)
            )
            
            # Anomaly traffic arrow
            painter.setPen(QPen(QColor(255, 0, 0, 255), 1.5))
            painter.drawLine(
                QPointF(legend_x2_anom, legend_y2_anom),
                QPointF(legend_x2_anom - arrow_size, legend_y2_anom - arrow_size/2)
            )
            painter.drawLine(
                QPointF(legend_x2_anom, legend_y2_anom),
                QPointF(legend_x2_anom - arrow_size, legend_y2_anom + arrow_size/2)
            )
            
            # End painting
            painter.end()
            
            print(f"Created QPixmap with world map: {pixmap.width()}x{pixmap.height()}")
            
            # Save pixmap to file for debugging
            image_path = "resources/packet_map.png"
            pixmap.save(image_path)
            print(f"Map saved to {image_path}")
            
            # Emit signal with pixmap to update UI from main thread
            self.pixmapReady.emit(pixmap)

        except Exception as e:
            import traceback
            print(f"Error in create_map function: {e}")
            print(traceback.format_exc())
    
    def run(self):
        print("GeoMap Thread is running...")
        self.create_map()
        print("GeoMap Thread finished")

class NetworkTopologyVisualizer(threading.Thread):
    def __init__(self, packetobj, ui):
        super().__init__()
        self.ui = ui
        self.list_of_nodes = []
        self.packetobj = packetobj
        try:
            # Layout for self.ui.widget_6
            self.layout = QVBoxLayout(self.ui.widget_6)
            
            # Clear any existing widgets in the layout
            if self.ui.widget_6.layout():
                while self.ui.widget_6.layout().count():
                    item = self.ui.widget_6.layout().takeAt(0)
                    if item.widget():
                        item.widget().deleteLater()

            self.figure = plt.figure(figsize=(6, 5))  # Reduced figure size
            self.canvas = FigureCanvas(self.figure)
            self.layout.addWidget(self.canvas)
            
            print("NetworkTopologyVisualizer initialized successfully")
        except Exception as e:
            import traceback
            print(f"Error initializing NetworkTopologyVisualizer: {e}")
            print(traceback.format_exc())

        self.start()

    def find_unique_devices_and_edges(self):
        try:
            print("Finding unique devices and edges...")
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
           
            print(f"Found {len(unique_ips)} unique IPs and {len(pure_local)} pure local packets")
            
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
            
            print(f"Successfully processed {len(self.list_of_nodes)} nodes with their connections")
            
        except Exception as e:
            import traceback
            print(f"Error in find_unique_devices_and_edges: {e}")
            print(traceback.format_exc())

    
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
        
        # Initialize visualization object first
        print("Initializing visualization objects...")
        self.Visualizationobj = visualization(self.main_window, self.ui)
        
        # Create a refresh button for the geomap
        self.refresh_button = QPushButton("Refresh Map")
        self.refresh_button.setObjectName("refreshMapButton")
        self.refresh_button.setMaximumWidth(120)
        self.ui.geoGroupBox.layout().insertWidget(0, self.refresh_button)
        self.refresh_button.clicked.connect(self.refresh_geomap)
        
        # Add a location label above the map
        self.location_label = QLabel("Detecting location...")
        self.location_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.location_label.setFont(font)
        self.location_label.setStyleSheet("color: #40E0D0;")  # Turquoise color to match theme
        self.ui.geoGroupBox.layout().insertWidget(0, self.location_label)
        
        # Then set up UI connections
        self.init_ui()
        
        try:
            print("Setting up 3D visualization...")
            self.ThreeDVisulizationobj = NetworkTopologyVisualizer(self.main_window.PacketSystemobj, self.ui)
        except Exception as e:
            print(f"Error initializing 3D visualization: {e}")
        
        try:
            print("Setting up GeoMap visualization...")
            # Make sure packets and anomalies exist and are accessible
            if hasattr(self.main_window.PacketSystemobj, 'packets') and self.main_window.PacketSystemobj.packets:
                print(f"Found {len(self.main_window.PacketSystemobj.packets)} packets")
                di.container.register_singleton("GeoMap", self.create_geo_map())
                self.GeoMapObj = di.container.resolve("GeoMap")
                self.GeoMapObj.set_ui(self.ui)
                # Update location label after GeoMap is created
                self.update_location_label()
            else:
                print("No packets available for the GeoMap")
        except Exception as e:
            import traceback
            print(f"Error initializing GeoMap: {e}")
            print(traceback.format_exc())

    def create_geo_map(self):
        packet_system = di.container.resolve("PacketSystem")
        return GeoMap(
            geo_mapper=MaxMindGeoMapper("resources/GeoLite2-City.mmdb"),
            packets=packet_system.packets,
            anomalies=packet_system.anomalies
        )
    
    def update_location_label(self):
        """Update the location label with the real location information"""
        if hasattr(GeoMap, 'real_location_name') and GeoMap.real_location_name:
            self.location_label.setText(f"Network Traffic Map (Real Location: {GeoMap.real_location_name})")
        else:
            self.location_label.setText("Network Traffic Map (Location: Unknown)")

    def refresh_geomap(self):
        """Refresh the geomap visualization"""
        try:
            print("Refreshing GeoMap...")
            # Re-initialize the GeoMap object
            if hasattr(self, 'GeoMapObj'):
                # Delete old thread if it exists
                self.GeoMapObj = None
                
            # Create new GeoMap
            di.container.register_singleton("GeoMap", self.create_geo_map())
            self.GeoMapObj = di.container.resolve("GeoMap")
            self.GeoMapObj.set_ui(self.ui)
            print("GeoMap refresh initiated")
            
            # Update the location label
            self.update_location_label()
            
        except Exception as e:
            import traceback
            print(f"Error refreshing GeoMap: {e}")
            print(traceback.format_exc())
            
    def init_ui(self):
        self.setWindowTitle("Secondary Widget")
        self.showMaximized()
        self.setWindowTitle("Naswail - Visualization")
        
        # Connect comboBox_2 selection change
        self.ui.comboBox_2.currentIndexChanged.connect(self.on_combobox_change)
        self.ui.comboBox_3.currentIndexChanged.connect(self.on_combobox_change)
        self.ui.comboBox_4.currentIndexChanged.connect(self.on_combobox_change)
        self.ui.comboBox_5.currentIndexChanged.connect(self.on_combobox_change)
        self.ui.comboBox_6.currentIndexChanged.connect(self.on_combobox_change)
        
        # Set up logo
        pixmap = QPixmap(r"resources/logo.jpg")  # Fixed to use logo.jpg instead of logo.png
        self.pixmap_item = QGraphicsPixmapItem(pixmap)
        self.scene = QGraphicsScene(self)
        self.scene.addItem(self.pixmap_item)
        self.ui.graphicsView.setScene(self.scene)
        self.ui.graphicsView.setFixedSize(71, 61)
        self.ui.graphicsView.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        
        # Connect navigation buttons
        self.ui.pushButton_4.clicked.connect(self.show_main_window)
        self.ui.pushButton_3.clicked.connect(self.show_tools_window)
        self.ui.pushButton_5.clicked.connect(self.show_incidentresponse_window)

        self.ui.label.setText("")
     
        # Initialize a placeholder for selected option
        self.selected_option = "Protocols"
        
        # Display all visualizations
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
