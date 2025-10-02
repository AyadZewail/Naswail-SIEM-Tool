import sys
import numpy as np
import threading
from datetime import datetime, timedelta
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from datetime import datetime, timedelta
from views.UI_Tools import Ui_Naswail_Tool
import time
import traceback
from core import di

class ToolsController():
    def __init__(
            self,
            ui,
            predmodel,
            netactv,
            packets,
            activityList,
            timeSeries,
            corrPackets,
            protocolExtractor,
    ):
        #======================================================================================
        #======================================================================================
        #                               Variable Instantiation
        #======================================================================================
        #======================================================================================
        self.ui = ui
        self.netActivityAnalyzer = netactv
        self.activityList = activityList
        self.packets = packets
        self.filecontent=""
        self.display_activity()

        self.futureTraffic = []
        self.r2 = 0
        self.noHours = None
        self.time_series = timeSeries
        self.prediction_running = False
        self.last_update_time = 0
        self.trafficPredictor = predmodel
        self.metrics = {}
        self.intervals = [1, 3, 6, 12, 24] 
        self.display_prediction() 
        
        self.error_packets = []
        self.corrupted_packet = corrPackets
        self.protocolExtractor = protocolExtractor
        self.last_packet_count = 0
        self.display_corrupted()
        self.sec = 0
 

        #======================================================================================
        #======================================================================================
        #                                 UI Mapping
        #======================================================================================
        #======================================================================================
        self.ui.tableWidget_6.setColumnCount(11)
        self.ui.tableWidget_6.setHorizontalHeaderLabels(
            ["Timestamp", "Source", "Destination", "Protocol", "Layer", "MAC Src", "MAC Dst", "Src Port", "Dst Port", "Length", "IP Version"]
        )

        self.ui.tableWidget_3.setColumnCount(2)
        self.ui.tableWidget_3.setRowCount(7)
        self.ui.tableWidget_3.setHorizontalHeaderLabels(["Time", "Packet Esitmate"])
        self.ui.tableWidget_3.setVerticalHeaderLabels(["Current", "Desired Time", "+ 1 Hour", "+ 3 Hour", "+ 6 Hour", "+ 12 Hour", "+ 24 Hour"])
        self.ui.pushButton.clicked.connect(self.setHours)
        self.ui.pushButton_6.clicked.connect(self.resetfilter)
        self.ui.pushButton_7.clicked.connect(self.display_activity)
        self.ui.pushButton_5.clicked.connect(self.save_activity)

    #======================================================================================
    #======================================================================================
    #                                 Network Activity
    #======================================================================================
    #======================================================================================
    def display_activity(self):
        try:
            self.activityList.clear()
            self.activityList.extend(self.netActivityAnalyzer.extract_activities(self.packets))
            self.filecontent=""
            formatted_content=[]
            for list_of_activity  in self.activityList:
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
    
    #======================================================================================
    #======================================================================================
    #                                 Network Prediction
    #======================================================================================
    #======================================================================================

    def pred_traffic(self):
        try:
            if self.prediction_running:
                return

            self.prediction_running = True

            # Only attempt training/prediction if data is sufficient
            if len(self.time_series) > 10:
                # Train the model
                self.trafficPredictor.train(packets=self.packets, time_series=self.time_series)

                # Predict using the trained model
                hours = self.noHours if self.noHours is not None else 1
                current_packet_count = len(self.packets)
                self.futureTraffic = self.trafficPredictor.predict(hours_ahead=hours, current_packet_count=current_packet_count, intervals=self.intervals)

                # Store all available metrics
                self.metrics = self.trafficPredictor.get_metrics()

            self.prediction_running = False
        except Exception as e:
            self.prediction_running = False
            print(f"[Prediction Error]: {e}")


    def setHours(self):
        try:
            if(self.ui.lineEdit.text() is None or self.ui.lineEdit.text() is object):
                self.ui.lineEdit.setText("0")
            self.noHours = int(self.ui.lineEdit.text())
        except Exception as e:
            print(e)
    
    def display_prediction(self):
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
            confidence = 0.1 * np.array(pred_values) * (1 + (1-max(0.1, self.metrics.get('r2', 0.0)))*2)
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
            ax2.annotate(f"R²: {self.metrics.get('r2', 0.0):.2f}", xy=(0.02, 0.02), xycoords='axes fraction', fontsize=8)
            
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

    
    #======================================================================================
    #======================================================================================
    #                                 Corrupted Packets
    #======================================================================================
    #======================================================================================
    def display_corrupted(self):
        try:
            # Only redraw if we have new packets
            current_count = len(self.corrupted_packet)
            if current_count == self.last_packet_count:
                return  # Skip redraw if no new packets
            
            # If table already has rows and we're just adding new ones
            if self.last_packet_count > 0 and current_count > self.last_packet_count:
                # Only process the new packets
                start_idx = self.last_packet_count
            else:
                # Full redraw
                self.ui.tableWidget_6.setRowCount(0)
                start_idx = 0
                
            # Update our packet count tracker
            self.last_packet_count = current_count
            
            # Add only the new packets
            for idx in range(start_idx, current_count):
                packet = self.corrupted_packet[idx]
                
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
                
                protocol = self.protocolExtractor.extract_protocol(packet)
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
            tb = traceback.format_exc()
            print("Traceback details:")
            print(tb)
    
    
    #======================================================================================
    #======================================================================================
    #                                 Misc Handling
    #======================================================================================
    #======================================================================================
    def ttTime(self):
        # Only update the error packet display - light operation
        self.display_corrupted()
        self.sec += 3  # Increment by 3 since we're running every 3 seconds
    
    def heavy_update(self):
        # Handle heavy operations on a separate timer
        try:
            # Run prediction if not already running
            if not self.prediction_running:
                self.pred_traffic()
                if self.metrics.get("r2", 0.0) > 0.50:
                    self.display_prediction()
                    self.display_advanced_graph()
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
        except Exception as e:
            print(f"Error in resetfilter function: {e}")



class Window_Tools(QWidget, Ui_Naswail_Tool):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Naswail - Tools")

        self.ui = Ui_Naswail_Tool()  
        self.ui.setupUi(self)  
        self.init_ui()

        self.controller = ToolsController(
            ui= self.ui,
            predmodel= di.container.resolve("regression_predictor"),
            netactv= di.container.resolve("network_activity_analyzer"),
            packets= di.container.resolve("packets"),
            activityList= di.container.resolve("list_of_activity"),
            timeSeries= di.container.resolve("time_series"),
            corrPackets= di.container.resolve("corrupted_packet_list"),
            protocolExtractor= di.container.resolve("protocol_extractor"),
        )
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.controller.ttTime)
        self.timer.start(3000)  # Update every 3 seconds instead of every 1 second
        
        # Set up a second, slower timer for heavy operations
        self.heavy_timer = QTimer(self)
        self.heavy_timer.timeout.connect(self.controller.heavy_update)
        self.heavy_timer.start(6000)
        
        # Add cleanup when window is closed
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    
    def init_ui(self):
        self.showMaximized()
        self.ui.pushButton_4.clicked.connect(self.show_main_window)
        self.ui.pushButton_2.clicked.connect(self.show_analysis_window)
        self.ui.pushButton_8.clicked.connect(self.show_incidentresponse_window)

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
