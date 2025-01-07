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
from tool import Ui_Naswail_Tool
class SecondaryWidget2(QWidget, Ui_Naswail_Tool):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window  # Reference to the main window

        self.ui = Ui_Naswail_Tool()  # Create an instance of the UI class
        self.ui.setupUi(self)  # Set up the UI for this widget
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Secondary Widget")
        self.showMaximized()
    def show_main_window(self):
        """Show the main window and hide this widget."""
        self.main_window.show()
        self.hide()



if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())
