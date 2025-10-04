# core/bootstrap.py
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from views.Home_VIew import Ui_MainWindow  # extracted your class here
from views.IncidentResponse_View import Ui_IncidentResponse, LogWindow  # extracted your class here
from views.Tools_View import Ui_Naswail_Tool  # extracted your class here
from views.Analysis_View import Ui_Naswail_Anlaysis  # extracted your class here
from controllers.Home_Controller import HomeController
from controllers.IncidentResponse_Controller import IncidentResponseController
from controllers.Tools_Controller import ToolsController
from controllers.Analysis_Controller import AnalysisController
from core import di
from PyQt6 import QtCore
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
import traceback

class Bootstrap:
    def __init__(self):
        pass

    def build(self):
        """Assemble and return the main application window."""
        # === Main Window ===
        self.main_window = QMainWindow()
        view = Ui_MainWindow()
        view.setupUi(self.main_window)
        self.main_window.showMaximized()
        self.main_window.setWindowTitle("Naswail - Main")

        # === Fix Navigation Bar ===
        self._fix_navigation_bar(view)

        # === Scene Setup ===
        scene = QGraphicsScene(self.main_window)

        # === Controller Wiring ===
        controller = HomeController(
            ui = view,
            packet_decoder = di.container.resolve("packet_decoder"),
            packet_details = di.container.resolve("packet_details"),
            protocol_extractor = di.container.resolve("protocol_extractor"),
            error_checker = di.container.resolve("error_checker"),
            packet_statistics = di.container.resolve("packet_statistics"),
            anomaly_detector = di.container.resolve("anomaly_detector"),
            packet_filter = di.container.resolve("packet_filter"),
            corrupted_packet_list = di.container.resolve("corrupted_packet_list"),
            network_log = di.container.resolve("network_log"),
            anomalies = di.container.resolve("anomalies"),
            blacklist = di.container.resolve("blacklist"),
            blocked_ports = di.container.resolve("blocked_ports"),
            list_of_activity = di.container.resolve("list_of_activity"),
            qued_packets = di.container.resolve("qued_packets"),
            packets = di.container.resolve("packets"),
            time_series = di.container.resolve("time_series"),
            sen_info = di.container.resolve("sen_info"),
            sensor_system = di.container.resolve("sensor_system"),
            application_system = di.container.resolve("application_system"),
            packet_exporter = di.container.resolve("packet_exporter"),
            scene = scene,
            totINpacekts= di.container.resolve("total_inside_packets"),
            totOUTpacekts= di.container.resolve("total_outside_packets"),
            packetStats= di.container.resolve("packet_stats"),
            bandwidthData= di.container.resolve("bandwidth_data"),
        )

        self.IR_Controller, self.IR_View, self.IR_Page = self.build_IR(self.main_window)
        self.Tools_Controller, self.Tools_View, self.Tools_Page = self.build_Tools()
        self.Analysis_Controller, self.Analysis_View, self.Analysis_page = self.build_Analysis()

        # === Navigation Wiring ===
        view.pushButton_2.clicked.connect(lambda: self.show_analysis_window(self.main_window))
        view.pushButton_3.clicked.connect(lambda: self.show_tools_window(self.main_window))
        view.pushButton_13.clicked.connect(lambda: self.show_incidentresponse_window(self.main_window))

        # === Notification Wiring ===
        view.notificationButton.clicked.connect(
            lambda: self._show_notifications(view)
        )
        view.notificationList.itemClicked.connect(
            lambda item: self._show_notification_details(view, item)
        )

        # Example: add a startup notification
        self._add_notification(view,
            "Ayad be goofing",
            "ayad has a tendency to goof quite hard these days, so he is a bit busy",
            "come on man its too ez..."
        )

        return self.main_window

    # ---------------- Helper wiring methods ----------------
    def _fix_navigation_bar(self, view):
        view.horizontalLayoutWidget.raise_()
        view.pushButton_4.raise_()
        view.pushButton_13.raise_()
        view.pushButton_3.raise_()
        view.pushButton_2.raise_()
        view.notificationButton.raise_()

    def _show_notifications(self, view):
        view.notificationMenu.exec(
            view.notificationButton.mapToGlobal(
                QtCore.QPoint(0, view.notificationButton.height())
            )
        )

    def _show_notification_details(self, view, item):
        notification_data = item.data(QtCore.Qt.ItemDataRole.UserRole)

        detail_dialog = QDialog(parent=view.centralwidget)
        detail_dialog.setWindowTitle("Notification Details")
        detail_dialog.setFixedSize(400, 400)

        layout = QVBoxLayout()
        detail_text = QTextEdit()
        detail_text.setReadOnly(True)
        detail_text.setStyleSheet("""
            QTextEdit {
                background-color: #3E3D40;
                color: #FFFFFF;
                border: 1px solid #5A595C;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
            }
        """)

        detail_text.setText(f"""
        {notification_data.get('title', 'Notification')}

        Time: {notification_data.get('timestamp', 'Unknown')}
        Severity: {notification_data.get('severity', 'Medium')}

        Details:
        {notification_data.get('details', 'No details available')}

        Full Report:
        {notification_data.get('full_details', 'No additional information')}
        """)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(detail_dialog.close)

        layout.addWidget(detail_text)
        layout.addWidget(close_btn)
        detail_dialog.setLayout(layout)
        detail_dialog.exec()

    def _add_notification(self, view, title, details="", full_details=""):
        item = QListWidgetItem(title)
        item.setData(QtCore.Qt.ItemDataRole.UserRole, {
            'title': title,
            'details': details,
            'full_details': full_details,
            'timestamp': QtCore.QDateTime.currentDateTime().toString(),
            'severity': 'High'
        })
        view.notificationList.addItem(item)

    # ---------------- Page Switching ----------------
    def show_tools_window(self, current):
        try:
            self.Tools_Page.show()
            current.hide()
        except Exception as e:
            print(f"Error in open_tool function: {e}")

    def show_analysis_window(self, current):
        try:
            self.Analysis_page.show()
            current.hide()
        except Exception as e:
            print(f"Error in open_analysis function: {e}")
            tb = traceback.format_exc()
            print(tb)

    def show_incidentresponse_window(self, current):
        try:
            self.IR_Page.show()
            current.hide()
        except Exception as e:
            print(f"Error in open_incidentresponse function: {e}")
            tb = traceback.format_exc()
            print(tb)
    
    def show_main_window(self, current):
        try:
            self.main_window.show()
            current.hide()
        except Exception as e:
            print(f"Error in show_main_window function: {e}")
            tb = traceback.format_exc()
            print(tb)

    
    #======================================================================================
    #======================================================================================
    #                            Incident Response Bootstrap
    #======================================================================================
    #======================================================================================
    def build_IR(self, main_window):
        main_window = self.main_window
        window = QWidget()
        view = Ui_IncidentResponse()
        view.setupUi(window)
        window.showMaximized()
        window.hide()

        model = QStandardItemModel()
        model.setHeaderData(0, Qt.Orientation.Horizontal, "Attack Log")
        view.treeView.setModel(model)
        view.treeView.setWordWrap(True)
        view.treeView.setUniformRowHeights(False)
        view.treeView.expandAll()
        logAutopilot = LogWindow(model)

        controller = IncidentResponseController(
            ui = view,
            anomalies = di.container.resolve("anomalies"),
            protocol_extractor = di.container.resolve("protocol_extractor"),
            autopilot_engine = di.container.resolve("autopilot"),
            threat_intel = di.container.resolve("threat_intelligence"),
            blacklist = di.container.resolve("blacklist"),
            blocked_ports = di.container.resolve("blocked_ports"),
            network_log = di.container.resolve("network_log"),
            mitigation_engine = di.container.resolve("ThreatMitigationEngine"),
            autopilot_log = logAutopilot,
            main_window = main_window
        )
        
        view.pushButton_8.clicked.connect(lambda: self.show_main_window(window))
        view.pushButton_7.clicked.connect(lambda: self.show_analysis_window(window))
        view.pushButton_6.clicked.connect(lambda: self.show_tools_window(window))

        timer = QTimer(window)
        timer.timeout.connect(controller.ttTime)
        timer.start(1000)

        return controller, view, window
    
    #======================================================================================
    #======================================================================================
    #                                   Tools Bootstrap
    #======================================================================================
    #======================================================================================
    def build_Tools(self):
        window = QWidget()
        window.setWindowTitle("Naswail - Tools")

        view = Ui_Naswail_Tool()  
        view.setupUi(window)

        window.showMaximized()
        window.hide()

        controller = ToolsController(
            ui= view,
            predmodel= di.container.resolve("regression_predictor"),
            netactv= di.container.resolve("network_activity_analyzer"),
            packets= di.container.resolve("packets"),
            activityList= di.container.resolve("list_of_activity"),
            timeSeries= di.container.resolve("time_series"),
            corrPackets= di.container.resolve("corrupted_packet_list"),
            protocolExtractor= di.container.resolve("protocol_extractor"),
        )

        view.pushButton_4.clicked.connect(lambda: self.show_main_window(window))
        view.pushButton_2.clicked.connect(lambda: self.show_analysis_window(window))
        view.pushButton_8.clicked.connect(lambda: self.show_incidentresponse_window(window))
          # Update every 3 seconds instead of every 1 second
        
        # Set up a second, slower timer for heavy operations
        heavy_timer = QTimer(window)
        heavy_timer.timeout.connect(controller.heavy_update)
        heavy_timer.start(6000)

        return controller, view, window
        
    #======================================================================================
    #======================================================================================
    #                                   Analysis Bootstrap
    #======================================================================================
    #======================================================================================
    def build_Analysis(self):
        window = QWidget()
        view = Ui_Naswail_Anlaysis()  # Create an instance of the UI class
        view.setupUi(window)
        window.showMaximized()
        window.hide()
        window.setWindowTitle("Naswail - Visualization")
        
        # Then set up UI connections
        pixmap = QPixmap(r"resources/logo.jpg")  # Fixed to use logo.jpg instead of logo.png
        pixmap_item = QGraphicsPixmapItem(pixmap)
        scene = QGraphicsScene(window)
        scene.addItem(pixmap_item)
        view.graphicsView.setScene(scene)
        view.graphicsView.setFixedSize(71, 61)
        view.graphicsView.fitInView(scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        
        # Connect navigation buttons
        view.pushButton_4.clicked.connect(lambda: self.show_main_window(window))
        view.pushButton_3.clicked.connect(lambda: self.show_tools_window(window))
        view.pushButton_5.clicked.connect(lambda: self.show_incidentresponse_window(window))

        view.label.setText("")

        try:
            # Layout for view.widget_6
            layout = QVBoxLayout(view.widget_6)
            
            # Clear any existing widgets in the layout
            if view.widget_6.layout():
                while view.widget_6.layout().count():
                    item = view.widget_6.layout().takeAt(0)
                    if item.widget():
                        item.widget().deleteLater()

            figure = plt.figure(figsize=(6, 5))  # Reduced figure size
            canvas = FigureCanvas(figure)
            layout.addWidget(canvas)
            
            print("NetworkTopologyVisualizer initialized successfully")
        except Exception as e:
            import traceback
            print(f"Error initializing NetworkTopologyVisualizer: {e}")
            print(traceback.format_exc())

        controller = AnalysisController(
            ui=view,
            queuedPacekts=di.container.resolve("qued_packets"),
            sensorSys=di.container.resolve("sensor_system"),
            totINpacekts=di.container.resolve("total_inside_packets"),
            totOUTpacekts=di.container.resolve("total_outside_packets"),
            packetStats=di.container.resolve("packet_stats"),
            sen_info=di.container.resolve("sen_info"),
            bandwidthData=di.container.resolve("bandwidth_data"),
            packets=di.container.resolve("packets"),
            anomalies=di.container.resolve("anomalies"),
            geo_mapper=di.container.resolve("geo_mapper"),
            figure= figure,
            canvas=canvas,
        )

        return controller, view, window