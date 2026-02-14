# main.py
import sys
import ctypes
import subprocess
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from core.bootstrap import Bootstrap
# from ui.splash import SplashScreen  # assuming you already have this
import platform

class SplashScreen(QSplashScreen):
    def __init__(self):
        # Get the screen dimensions
        screen = QApplication.primaryScreen().size()
        screen_width = screen.width()
        screen_height = screen.height()
        
        logo_path = "resources/logo.png"
        pixmap = QPixmap(logo_path)
        
        # If logo.png doesn't exist, try the alternative name
        if pixmap.isNull():
            logo_path = "resources/naswail_logo.png"
            pixmap = QPixmap(logo_path)
        
        # Create a larger canvas for full screen
        if not pixmap.isNull():
            # Scale logo to appropriate size (not too large, not too small)
            logo_height = int(screen_height * 0.4)  # 40% of screen height
            scaled_pixmap = pixmap.scaled(logo_height, logo_height, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            
            # Create a new full-size pixmap with background color
            full_pixmap = QPixmap(screen_width, screen_height)
            full_pixmap.fill(QColor("#17292B"))  # Dark background color
            
            # Create a painter to draw on the full pixmap
            painter = QPainter(full_pixmap)
            
            # Draw the logo in the center
            logo_x = (screen_width - scaled_pixmap.width()) // 2
            logo_y = (screen_height - scaled_pixmap.height()) // 2 - 50  # Slight offset for progress bar
            painter.drawPixmap(logo_x, logo_y, scaled_pixmap)
            painter.end()
            
            pixmap = full_pixmap
        
        super().__init__(pixmap)
        
        # Set window as frameless and fullscreen
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        
        # Progress bar setup
        progress_width = int(screen_width * 0.6)  # 60% of screen width
        progress_height = 40
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(
            (screen_width - progress_width) // 2,  # center horizontally 
            logo_y + scaled_pixmap.height() + 50,  # position below the logo
            progress_width, 
            progress_height
        )
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #5A595C;
                border-radius: 5px;
                background-color: #2D2A2E;
                text-align: center;
                color: white;
                font-size: 14pt;
            }
            
            QProgressBar::chunk {
                background-color: #9CB7C8;
                width: 10px;
                margin: 0.5px;
            }
        """)
        
        # Add label for text
        self.label = QLabel("Loading...", self)
        self.label.setStyleSheet("color: white; font-size: 18pt; font-weight: bold; background: transparent;")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setGeometry(0, self.progress_bar.y() - 60, screen_width, 50)
        
        # Timer for progress updates
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.progress_value = 0
        
        # Loading messages
        self.loading_messages = [
            "Starting Naswail SIEM...",
            "Loading network modules...",
            "Initializing packet capture...",
            "Setting up analysis engine...",
            "Loading security components...",
            "Preparing interface...",
            "Almost ready..."
        ]
        self.message_index = 0
    
    def start_progress(self):
        self.timer.start(30)
        
    def update_progress(self):
        self.progress_value += 1
        self.progress_bar.setValue(self.progress_value)
        
        # Update loading message periodically
        if self.progress_value % 14 == 0 and self.message_index < len(self.loading_messages):
            self.label.setText(self.loading_messages[self.message_index])
            self.message_index += 1
            
        # When progress reaches 100, stop the timer
        if self.progress_value >= 100:
            self.timer.stop()
    
    # Override mousePressEvent to prevent clicking through splash screen
    def mousePressEvent(self, event):
        pass
  

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_command_as_admin():
    cmd_command = 'snort -i 5 -c C:\\Snort\\etc\\snort.conf -l C:\\Snort\\log -A fast'
    subprocess.Popen(
        ['cmd.exe', '/k', cmd_command],
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # splash screen
    splash = SplashScreen()
    splash.show()
    splash.start_progress()

    # build app using bootstrap
    bootstrap = Bootstrap()
    window = bootstrap.build()

    # transition after splash
    def finish_loading():
        if is_admin():
            run_command_as_admin()

        splash.finish(window)
        window.show()
        window.activateWindow()
        window.raise_()

        if platform.system() == "Windows":
            try:
                ctypes.windll.user32.SetForegroundWindow(int(window.winId()))
            except:
                pass

    QTimer.singleShot(1000, finish_loading)

    sys.exit(app.exec())
