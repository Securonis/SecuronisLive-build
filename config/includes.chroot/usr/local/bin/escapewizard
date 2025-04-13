#!/usr/bin/env python3
import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, 
                           QVBoxLayout, QHBoxLayout, QWidget, QLabel,
                           QMessageBox, QGridLayout)
from PyQt5.QtGui import QIcon, QPixmap, QFont
from PyQt5.QtCore import Qt
import subprocess

class EscapeWizard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Escape Wizard")
        self.setFixedSize(700, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 16px;
            }
            QMessageBox {
                background-color: #2d2d2d;
                color: white;
            }
            QMessageBox QLabel {
                color: white;
            }
            QMessageBox QPushButton {
                background-color: #8B0000;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 5px 15px;
                font-size: 12px;
            }
        """)
        
     
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
       
        title_label = QLabel("Escape Wizard")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #ff3333; margin: 20px;")
        main_layout.addWidget(title_label)
        
        
        desc_label = QLabel("Secure Trace Eraser Tool")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet("color: #cccccc; font-size: 16px; margin: 10px;")
        main_layout.addWidget(desc_label)
        
      
        grid_widget = QWidget()
        grid_layout = QGridLayout()
        grid_layout.setSpacing(15)
        grid_layout.setContentsMargins(0, 10, 0, 10)
        
       
        grid_container = QWidget()
        grid_container_layout = QHBoxLayout()
        grid_container_layout.setContentsMargins(0, 0, 0, 0)
        
    
        button_style = """
        QPushButton {
            background-color: #8B0000;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px;
            font-size: 13px;
            min-width: 160px;
            max-width: 160px;
            margin: 5px;
        }
        QPushButton:hover {
            background-color: #A00000;
        }
        QPushButton:pressed {
            background-color: #6B0000;
        }
        """
        
    
        self.system_button = QPushButton("Delete System Traces")
        self.cache_button = QPushButton("Delete Cache Files")
        self.network_button = QPushButton("Delete Network Traces")
        self.browser_button = QPushButton("Delete Browser Traces")
        self.all_button = QPushButton("Delete All Traces")
        self.exit_button = QPushButton("Exit")
        
       
        grid_layout.setHorizontalSpacing(35)  
        grid_layout.setVerticalSpacing(20)    
        
     
        buttons_container = QWidget()
        buttons_container.setFixedWidth(620)  
        
        buttons = [
            (self.system_button, 0, 0),
            (self.cache_button, 0, 1),
            (self.network_button, 0, 2),
            (self.browser_button, 1, 0),
            (self.all_button, 1, 1),
            (self.exit_button, 1, 2)
        ]
        
        for button, row, col in buttons:
            button.setStyleSheet(button_style)
            button.setFixedWidth(160)  
            grid_layout.addWidget(button, row, col, Qt.AlignCenter)
        
        grid_widget.setLayout(grid_layout)
        buttons_container.setLayout(grid_layout)
        
       
        container_layout = QHBoxLayout()
        container_layout.addStretch(1)
        container_layout.addWidget(buttons_container)
        container_layout.addStretch(1)
        
        grid_container.setLayout(container_layout)
        main_layout.addWidget(grid_container, 0, Qt.AlignCenter)  
        

        main_layout.addStretch()
        
       
        logo_container = QWidget()
        logo_layout = QHBoxLayout()
        logo_layout.setContentsMargins(0, 0, 0, 0) 
        logo_layout.setAlignment(Qt.AlignCenter)
        
        logo_label = QLabel()
        logo_label.setFixedSize(220, 220)
        logo_label.setStyleSheet("background-color: transparent;")
        logo_label.setPixmap(QPixmap("/usr/share/icons/securonis/wizard.png").scaled(220, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setAlignment(Qt.AlignCenter)
        
        logo_layout.addWidget(logo_label)
        logo_container.setLayout(logo_layout)
        main_layout.addWidget(logo_container)
        
       
        main_layout.setContentsMargins(20, 20, 20, 0)
        
    
        self.system_button.clicked.connect(lambda: self.delete_traces("system"))
        self.cache_button.clicked.connect(lambda: self.delete_traces("cache"))
        self.network_button.clicked.connect(lambda: self.delete_traces("network"))
        self.browser_button.clicked.connect(lambda: self.delete_traces("browser"))
        self.all_button.clicked.connect(self.delete_all_traces)
        self.exit_button.clicked.connect(self.close)
        
        main_layout.setSpacing(20)
        main_layout.setAlignment(Qt.AlignCenter)
        
    def delete_traces(self, trace_type):
        try:
            if trace_type == "system":
                subprocess.run(['bleachbit', '--clean', 'system.* tmp.* memory.*'])
            elif trace_type == "cache":
                subprocess.run(['bleachbit', '--clean', 'system.cache system.tmp thumbnails.cache'])
            elif trace_type == "network":
                subprocess.run(['bleachbit', '--clean', 'network.* system.network'])
            elif trace_type == "browser":
                subprocess.run(['bleachbit', '--clean', 'firefox.* chrome.* opera.*'])
            
            self.show_success_message(f"{trace_type.capitalize()} traces deleted successfully!")
        except Exception as e:
            self.show_error_message(f"Error occurred: {str(e)}")
        
    def delete_all_traces(self):
        try:
            subprocess.run(['bleachbit', '--clean', 'system.* browser.* network.* tmp.* memory.* thumbnails.*'])
            self.show_success_message("All traces deleted successfully!")
        except Exception as e:
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
