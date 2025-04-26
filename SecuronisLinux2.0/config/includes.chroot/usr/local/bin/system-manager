#!/usr/bin/env python3
import sys
import os
import subprocess
import psutil
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QPushButton, QTextEdit,
                           QMessageBox, QTabWidget, QFrame, QScrollArea,
                           QGridLayout, QProgressBar)
from PyQt5.QtCore import Qt, QSize, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QIcon, QPixmap, QPalette, QColor, QLinearGradient

class ModernButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #4d4d4d;
            }
            QPushButton:pressed {
                background-color: #1d1d1d;
            }
        """)
        self.setCursor(Qt.PointingHandCursor)

class SystemMonitor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
        # 
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(2000)  # 
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # 
        progress_style = """
            QProgressBar {
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                text-align: center;
                background-color: #2d2d2d;
            }
            QProgressBar::chunk {
                background-color: #42d4d4;
            }
        """
        
        # CPU RAM DISK
        for name in ["CPU", "RAM", "Disk"]:
            item_layout = QHBoxLayout()
            label = QLabel(f"{name}:")
            label.setStyleSheet("color: white; font-weight: bold;")
            progress = QProgressBar()
            progress.setStyleSheet(progress_style)
            item_layout.addWidget(label)
            item_layout.addWidget(progress)
            layout.addLayout(item_layout)
            setattr(self, f"{name.lower()}_bar", progress)
        
        self.setLayout(layout)
        
    def update_stats(self):
        # CPU usage
        cpu_percent = psutil.cpu_percent()
        self.cpu_bar.setValue(int(cpu_percent))
        self.cpu_bar.setFormat(f"CPU: {cpu_percent}%")
        
        # RAM usage
        ram = psutil.virtual_memory()
        self.ram_bar.setValue(int(ram.percent))
        self.ram_bar.setFormat(f"RAM: {ram.percent}%")
        
        # DISK usage 
        disk = psutil.disk_usage('/')
        self.disk_bar.setValue(int(disk.percent))
        self.disk_bar.setFormat(f"Disk: {disk.percent}%")

class SystemManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Securonis Linux System Manager")
        self.setGeometry(100, 100, 800, 600)
        
        # main widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # 
        left_panel = QWidget()
        left_panel.setFixedWidth(300)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(10)
        
        # Logo
        self.logo_label = QLabel()
        logo_pixmap = QPixmap("/usr/share/icons/securonis/logo2.png")
        if not logo_pixmap.isNull():
            self.logo_pixmap = logo_pixmap.scaled(150, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(self.logo_pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(self.logo_label)
        
        # 
        self.system_monitor = SystemMonitor()
        left_layout.addWidget(self.system_monitor)
        
        # 
        grid_layout = QGridLayout()
        grid_layout.setSpacing(5)
        
        # 
        button_style = """
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #4d4d4d;
            }
            QPushButton:pressed {
                background-color: #1d1d1d;
            }
            QPushButton:disabled {
                background-color: #1d1d1d;
                color: #666666;
            }
        """
        
        # Menu
        menu_buttons = [
            ("Update System", self.update_system),
            ("Firmware Update", self.update_firmware),
            ("System Info", self.system_info),
            ("Disk Info", self.disk_info),
            ("Internet Test", self.internet_test),
            ("Packages", self.list_packages),
            ("Memory", self.memory_usage),
            ("CPU Info", self.cpu_info),
            ("Network", self.network_connections),
            ("Clear Cache", self.clear_cache),
            ("Drivers", self.check_drivers),
            ("About", self.show_about),
            ("Help", self.show_help),
            ("Exit", self.close)
        ]
        
        self.buttons = {}  # hide butons
        for i, (text, callback) in enumerate(menu_buttons):
            btn = QPushButton(text)
            btn.setStyleSheet(button_style)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(callback)
            grid_layout.addWidget(btn, i//2, i%2)
            self.buttons[text] = btn
        
        left_layout.addLayout(grid_layout)
        left_layout.addStretch()
        main_layout.addWidget(left_panel)
        
        # 
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # 
        logs_label = QLabel("Logs:")
        logs_label.setStyleSheet("color: white; font-weight: bold; font-size: 14px; padding: 5px;")
        right_layout.addWidget(logs_label)
        
        # 
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #42d4d4; font-weight: bold; font-size: 12px; padding: 5px;")
        right_layout.addWidget(self.status_label)
        
        # frame
        output_frame = QFrame()
        output_frame.setStyleSheet("background-color: #1e1e1e; border: 1px solid #3d3d3d; border-radius: 4px;")
        output_frame_layout = QVBoxLayout(output_frame)
        output_frame_layout.setContentsMargins(0, 0, 0, 0)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: none;
                padding: 12px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                line-height: 1.6;
                selection-background-color: #3d3d3d;
                selection-color: #ffffff;
            }
            QTextEdit:focus { border: none; }
            QScrollBar:vertical {
                border: none;
                background-color: #1e1e1e;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #3d3d3d;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover { background-color: #4d4d4d; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        """)
        output_frame_layout.addWidget(self.output_text)
        
        right_layout.addWidget(output_frame)
        main_layout.addWidget(right_panel)
        
        # theme dark
        self.set_dark_theme()
        
    def set_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(35, 35, 35))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(35, 35, 35))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)
        
    def run_command(self, command, button_text=None):
        try:
            # 
            if button_text and button_text in self.buttons:
                self.buttons[button_text].setEnabled(False)
            
            # 
            self.output_text.setText("Processing...")
            QApplication.processEvents()  # Update interface
            
            # run the command
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            # update 
            self.output_text.setText(result.stdout)
            if result.stderr:
                self.output_text.append("\nErrors:\n" + result.stderr)
            
        except Exception as e:
            self.output_text.setText(f"Error: {str(e)}")
        finally:
            # 
            if button_text and button_text in self.buttons:
                self.buttons[button_text].setEnabled(True)
            
    def update_system(self):
        self.status_label.setText("Updating system...")
        self.output_text.clear()
        
        try:
            # Update progress
            update_process = subprocess.Popen(['sudo', 'apt-get', 'update'], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE,
                                           universal_newlines=True)
            
            while True:
                output = update_process.stdout.readline()
                if output == '' and update_process.poll() is not None:
                    break
                if output:
                    self.output_text.append(output.strip())
                    QApplication.processEvents()
            
            # Upgrade progress
            upgrade_process = subprocess.Popen(['sudo', 'apt-get', 'upgrade', '-y'],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            universal_newlines=True)
            
            while True:
                output = upgrade_process.stdout.readline()
                if output == '' and upgrade_process.poll() is not None:
                    break
                if output:
                    self.output_text.append(output.strip())
                    QApplication.processEvents()
            
            self.status_label.setText("System update completed!")
            QMessageBox.information(self, "Success", "System has been successfully updated!")
            
        except Exception as e:
            self.status_label.setText("Error occurred!")
            self.output_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred while updating the system: {str(e)}")
        
    def system_info(self):
        self.output_text.clear()
        try:
            # Kernel version without -e
            kernel = subprocess.check_output(['uname', '-r']).decode().strip()
            self.output_text.append(f"Kernel Version: {kernel}")
            
            # Other system info
            os_info = subprocess.check_output(['lsb_release', '-a']).decode()
            self.output_text.append("\nOperating System Information:")
            self.output_text.append(os_info)
            
        except Exception as e:
            self.output_text.append(f"Error: {str(e)}")
        
    def disk_info(self):
        self.run_command("df -h", "Disk Info")
        
    def internet_test(self):
        try:
            # 
            if "Internet Test" in self.buttons:
                self.buttons["Internet Test"].setEnabled(False)
            
            # 
            self.output_text.setText("Testing internet connection...")
            QApplication.processEvents()
            
            # 
            result = subprocess.run("ping -c 1 google.com", shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.output_text.setText("Internet connection is working!")
            else:
                self.output_text.setText("No internet connection!")
            
        except Exception as e:
            self.output_text.setText("Error checking internet connection!")
        finally:
            # 
            if "Internet Test" in self.buttons:
                self.buttons["Internet Test"].setEnabled(True)
        
    def list_packages(self):
        self.run_command("dpkg -l", "Packages")
        
    def memory_usage(self):
        self.run_command("free -h", "Memory")
        
    def cpu_info(self):
        self.run_command("lscpu", "CPU Info")
        
    def network_connections(self):
        self.run_command("ip a", "Network")
        
    def clear_cache(self):
        self.run_command("sudo sync && sudo echo 3 > /proc/sys/vm/drop_caches && sudo apt clean && sudo apt autoremove -y", "Clear Cache")
        
    def check_drivers(self):
        self.run_command("sudo lshw -C display", "Drivers")
        
    def show_about(self):
        self.output_text.clear()
        self.output_text.append("Securonis Linux System Manager")
        self.output_text.append("Version: 2.2")
        self.output_text.append("\nDeveloper: root0emir")
        self.output_text.append("\nWebsite: https://securonis.github.io")
        self.output_text.append("Github: https://github.com/securonis/system-manager")
        
    def show_help(self):
        QMessageBox.information(self, "Help",
                              "This application provides various system management tools:\n\n"
                              "1. Update System: Update your system packages\n"
                              "2. Firmware Update: Update system firmware\n"
                              "3. System Information: View OS and kernel information\n"
                              "4. Disk Information: View disk usage\n"
                              "5. Internet Test: Test your internet connection\n"
                              "6. Installed Packages: List all installed packages\n"
                              "7. Memory Usage: View memory usage\n"
                              "8. CPU Information: View CPU details\n"
                              "9. Network Connections: View network interfaces\n"
                              "10. Clear Cache: Clear system cache\n"
                              "11. Check Drivers: View display drivers\n"
                              "12. About: View application information\n"
                              "13. Help: Show this help message\n"
                              "14. Exit: Close the application")

    def update_firmware(self):
        self.status_label.setText("Updating firmware...")
        self.output_text.clear()
        
        try:
            # Run firmware update command
            update_process = subprocess.Popen(
                'sudo apt update && sudo apt install -y fwupd && sudo fwupdmgr refresh --force && sudo fwupdmgr get-updates && sudo fwupdmgr update -y',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            while True:
                output = update_process.stdout.readline()
                if output == '' and update_process.poll() is not None:
                    break
                if output:
                    self.output_text.append(output.strip())
                    QApplication.processEvents()
            
            self.status_label.setText("Firmware update completed!")
            QMessageBox.information(self, "Success", "Firmware update process completed!")
            
        except Exception as e:
            self.status_label.setText("Error occurred!")
            self.output_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred while updating firmware: {str(e)}")

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = SystemManager()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
