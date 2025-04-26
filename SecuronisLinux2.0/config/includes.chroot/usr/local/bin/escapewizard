#!/usr/bin/env python3

import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, 
                           QVBoxLayout, QHBoxLayout, QWidget, QLabel,
                           QMessageBox, QGridLayout, QFrame, QProgressBar)
from PyQt5.QtGui import QIcon, QPixmap, QFont, QColor, QPalette
from PyQt5.QtCore import Qt, QSize, QTimer
import subprocess

class EscapeWizard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Escape Wizard")
        self.setFixedSize(700, 500)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 14px;
            }
            QMessageBox {
                background-color: #2d2d2d;
                color: white;
            }
            QMessageBox QLabel {
                color: white;
                font-size: 12px;
            }
            QMessageBox QPushButton {
                background-color: #8B0000;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 5px 15px;
                font-size: 11px;
            }
            QFrame {
                background-color: #2d2d2d;
                border-radius: 15px;
            }
            QProgressBar {
                border: 2px solid #8B0000;
                border-radius: 5px;
                text-align: center;
                background-color: #1a1a1a;
            }
            QProgressBar::chunk {
                background-color: #8B0000;
                width: 10px;
            }
        """)
        

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(10)
        
        # Başlık
        title_label = QLabel("Escape Wizard")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff3333;
            margin: 10px;
            font-family: 'Segoe UI', Arial;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
        """)
        main_layout.addWidget(title_label)
        
  
        desc_label = QLabel("Escape Wizard is a simple GUI tool for clearing system traces.")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet("""
            color: #cccccc;
            font-size: 14px;
            margin: 5px;
            font-family: 'Segoe UI', Arial;
        """)
        main_layout.addWidget(desc_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #8B0000;
                border-radius: 5px;
                text-align: center;
                background-color: #1a1a1a;
            }
            QProgressBar::chunk {
                background-color: #8B0000;
                width: 10px;
            }
        """)
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)
        

        buttons_frame = QFrame()
        buttons_frame.setStyleSheet("""
            QFrame {
                background-color: #2d2d2d;
                border-radius: 15px;
                padding: 15px;
            }
        """)
        

        grid_layout = QGridLayout()
        grid_layout.setSpacing(15)
        grid_layout.setContentsMargins(0, 5, 0, 5)
        
    
        button_style = """
        QPushButton {
            background-color: #8B0000;
            color: white;
            border: none;
            border-radius: 8px;
            padding: 10px;
            font-size: 12px;
            min-width: 160px;
            max-width: 160px;
            margin: 3px;
            font-family: 'Segoe UI', Arial;
        }
        QPushButton:hover {
            background-color: #A00000;
            transform: scale(1.02);
        }
        QPushButton:pressed {
            background-color: #6B0000;
        }
        """
        

        self.system_button = QPushButton("Delete System Traces")
        self.cache_button = QPushButton("Delete Cache Files")
        self.network_button = QPushButton("Delete Network Traces")
        self.browser_button = QPushButton("Delete Browser Traces")
        self.downloads_button = QPushButton("Delete Downloads")
        self.recent_files_button = QPushButton("Delete Recent Files")
        self.temp_button = QPushButton("Delete Temp Files")
        self.logs_button = QPushButton("Delete Logs")
        self.clipboard_button = QPushButton("Clear Clipboard")
        self.thumbnails_button = QPushButton("Delete Thumbnails")
        self.all_button = QPushButton("Delete All")
        self.exit_button = QPushButton("Exit")
 
        grid_layout.setHorizontalSpacing(20)
        grid_layout.setVerticalSpacing(15)
        
        buttons = [
            (self.system_button, 0, 0),
            (self.cache_button, 0, 1),
            (self.network_button, 0, 2),
            (self.browser_button, 1, 0),
            (self.downloads_button, 1, 1),
            (self.recent_files_button, 1, 2),
            (self.temp_button, 2, 0),
            (self.logs_button, 2, 1),
            (self.clipboard_button, 2, 2),
            (self.thumbnails_button, 3, 0),
            (self.all_button, 3, 1),
            (self.exit_button, 3, 2)
        ]
        
        for button, row, col in buttons:
            button.setStyleSheet(button_style)
            button.setFixedWidth(160)
            grid_layout.addWidget(button, row, col, Qt.AlignCenter)
        
        buttons_frame.setLayout(grid_layout)
        main_layout.addWidget(buttons_frame)
        
        # Buton bağlantıları
        self.system_button.clicked.connect(lambda: self.delete_traces("system"))
        self.cache_button.clicked.connect(lambda: self.delete_traces("cache"))
        self.network_button.clicked.connect(lambda: self.delete_traces("network"))
        self.browser_button.clicked.connect(lambda: self.delete_traces("browser"))
        self.downloads_button.clicked.connect(lambda: self.delete_traces("downloads"))
        self.recent_files_button.clicked.connect(lambda: self.delete_traces("recent"))
        self.temp_button.clicked.connect(lambda: self.delete_traces("temp"))
        self.logs_button.clicked.connect(lambda: self.delete_traces("logs"))
        self.clipboard_button.clicked.connect(lambda: self.delete_traces("clipboard"))
        self.thumbnails_button.clicked.connect(lambda: self.delete_traces("thumbnails"))
        self.all_button.clicked.connect(self.delete_all_traces)
        self.exit_button.clicked.connect(self.close)
        
    def delete_traces(self, trace_type):
        try:
            self.progress_bar.setValue(0)
            self.progress_bar.show()
            
            if trace_type == "system":
                subprocess.run(['bleachbit', '--clean', 'system.* tmp.* memory.* swap.*'])
            elif trace_type == "cache":
                subprocess.run(['bleachbit', '--clean', 'system.cache system.tmp thumbnails.cache apt.cache'])
            elif trace_type == "network":
                subprocess.run(['bleachbit', '--clean', 'network.* system.network dns.cache'])
            elif trace_type == "browser":
                subprocess.run(['bleachbit', '--clean', 'firefox.* chrome.* opera.* brave.* vivaldi.* edge.*'])
            elif trace_type == "downloads":
                subprocess.run(['bleachbit', '--clean', 'downloads.*'])
            elif trace_type == "recent":
                subprocess.run(['bleachbit', '--clean', 'recent_documents.*'])
            elif trace_type == "temp":
                subprocess.run(['bleachbit', '--clean', 'system.tmp system.temp'])
            elif trace_type == "logs":
                subprocess.run(['bleachbit', '--clean', 'system.logs system.log'])
            elif trace_type == "clipboard":
                subprocess.run(['xsel', '-c'])  # Linux clipboard temizleme
            elif trace_type == "thumbnails":
                subprocess.run(['bleachbit', '--clean', 'thumbnails.*'])
            
            self.progress_bar.setValue(100)
            QTimer.singleShot(1000, self.progress_bar.hide)  # 1 saniye sonra progress bar'ı gizle
            self.show_success_message(f"{trace_type.capitalize()} traces deleted successfully!")
        except Exception as e:
            self.progress_bar.hide()
            self.show_error_message(f"Error occurred: {str(e)}")
        
    def delete_all_traces(self):
        try:
            self.progress_bar.setValue(0)
            self.progress_bar.show()
            
            subprocess.run(['bleachbit', '--clean', 'system.* browser.* network.* tmp.* memory.* thumbnails.* downloads.* recent_documents.* system.logs'])
            subprocess.run(['xsel', '-c'])  # Clipboard'ı da temizle
            
            self.progress_bar.setValue(100)
            QTimer.singleShot(1000, self.progress_bar.hide)
            self.show_success_message("All traces deleted successfully!")
        except Exception as e:
            self.progress_bar.hide()
            self.show_error_message(f"Error occurred: {str(e)}")
    
    def show_success_message(self, message):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setText(message)
        msg.setWindowTitle("Success")
        msg.exec_()
        
    def show_error_message(self, message):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Critical)
        msg.setText(message)
        msg.setWindowTitle("Error")
        msg.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = EscapeWizard()
    window.show()
    sys.exit(app.exec_()) 
