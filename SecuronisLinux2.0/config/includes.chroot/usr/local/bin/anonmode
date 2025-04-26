#!/usr/bin/env python3

import sys
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QPushButton, QLabel, QMessageBox, QHBoxLayout)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor, QPixmap, QIcon

class CommandThread(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, command):
        super().__init__()
        self.command = command

    def run(self):
        try:
            result = subprocess.run(['sudo', '/usr/sbin/anonymous', self.command], 
                                 capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                self.finished.emit(result.stdout)
            else:
                self.error.emit(f"Command failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            self.error.emit("Command timed out after 30 seconds")
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")

class AnonModeGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Securonis Anonymous Mode")
        self.setFixedSize(600, 400)
        
        # Window icon
        try:
            self.setWindowIcon(QIcon('/usr/share/icons/securonis/icon1.png'))
        except:
            pass  # Continue silently if icon cannot be loaded
        
        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setAlignment(Qt.AlignCenter)
        
        # Horizontal layout for title and icon
        title_layout = QHBoxLayout()
        title_layout.setAlignment(Qt.AlignCenter)
        title_layout.setSpacing(5)
        title_layout.setContentsMargins(0, 0, 0, 0)
        
        # Icon
        icon_label = QLabel()
        try:
            icon_pixmap = QPixmap('/usr/share/icons/securonis/icon1.png')
            icon_label.setPixmap(icon_pixmap.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        except:
            pass  # Continue silently if icon cannot be loaded
        icon_label.setContentsMargins(0, 0, 0, 0)
        title_layout.addWidget(icon_label)
        
        # Title
        title = QLabel("Securonis Anonymous Mode")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setContentsMargins(0, 0, 0, 0)
        title_layout.addWidget(title)
        
        layout.addLayout(title_layout)
        
        # Description text
        description = QLabel(
            "This tool configures Securonis Linux to maximize online "
            "anonymity and privacy using the Tor network.\n\n"
            "Note: Carefully review this tool before use. Ensure that you "
            "operate within legal boundaries and adhere to ethical guidelines."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        layout.addWidget(description)
        
        # Buttons
        self.start_btn = QPushButton("Start Anonymous Mode")
        self.stop_btn = QPushButton("Stop Anonymous Mode")
        self.status_btn = QPushButton("Status of Anonymous Mode")
        
        # Button styles
        for btn in [self.start_btn, self.stop_btn, self.status_btn]:
            btn.setFixedWidth(250)
            btn.setFixedHeight(40)
            btn.setFont(QFont("Arial", 10))
            layout.addWidget(btn, alignment=Qt.AlignCenter)
        
        # Button connections
        self.start_btn.clicked.connect(self.start_anonymous)
        self.stop_btn.clicked.connect(self.stop_anonymous)
        self.status_btn.clicked.connect(self.check_status)
        
        # Dark theme style settings
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QWidget {
                background-color: #1e1e1e;
            }
            QLabel {
                color: #ffffff;
                margin: 10px;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3d3d3d;
                border-radius: 5px;
                margin: 5px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #4d4d4d;
            }
            QPushButton:pressed {
                background-color: #4d4d4d;
            }
            QMessageBox {
                background-color: #1e1e1e;
            }
            QMessageBox QLabel {
                color: #ffffff;
            }
            QMessageBox QPushButton {
                min-width: 80px;
                min-height: 25px;
            }
        """)

    def disable_buttons(self):
        """Disable all buttons"""
        for btn in [self.start_btn, self.stop_btn, self.status_btn]:
            btn.setEnabled(False)

    def enable_buttons(self):
        """Enable all buttons"""
        for btn in [self.start_btn, self.stop_btn, self.status_btn]:
            btn.setEnabled(True)

    def show_message(self, title, message):
        """Show message box"""
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #1e1e1e;
            }
            QMessageBox QLabel {
                color: #ffffff;
            }
            QMessageBox QPushButton {
                min-width: 80px;
                min-height: 25px;
            }
        """)
        msg.exec_()

    def run_command(self, command):
        """Run command in a separate thread"""
        self.disable_buttons()
        self.thread = CommandThread(command)
        self.thread.finished.connect(lambda output: self.handle_command_result(command, output))
        self.thread.error.connect(lambda error: self.handle_command_error(command, error))
        self.thread.start()

    def handle_command_result(self, command, output):
        """Handle successful command execution"""
        self.enable_buttons()
        self.show_message(f"{command.title()} Anonymous Mode", output)

    def handle_command_error(self, command, error):
        """Handle command execution error"""
        self.enable_buttons()
        self.show_message("Error", error)

    def start_anonymous(self):
        self.run_command('start')

    def stop_anonymous(self):
        self.run_command('stop')

    def check_status(self):
        self.run_command('status')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AnonModeGUI()
    window.show()
    sys.exit(app.exec_()) 
