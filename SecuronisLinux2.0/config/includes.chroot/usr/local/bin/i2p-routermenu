#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                            QMessageBox, QFrame, QSizePolicy)
from PyQt5.QtGui import QPixmap, QFont, QPalette, QColor, QIcon
from PyQt5.QtCore import Qt, QSize

# I2P Router Menu for Securonis Linux
# Developer root0emir	

class I2PRouterMenu(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("I2P Router Menu")
        self.setMinimumSize(500, 300)
        
        # Main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Logo
        self.logo_label = QLabel()
        self.logo_pixmap = QPixmap("/usr/share/icons/securonis/i2p.png")
        if not self.logo_pixmap.isNull():
            self.logo_pixmap = self.logo_pixmap.scaled(400, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(self.logo_pixmap)
        else:
            self.logo_label.setText("I2P ROUTER MENU")
            self.logo_label.setAlignment(Qt.AlignCenter)
            self.logo_label.setFont(QFont("Arial", 24, QFont.Bold))
        
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(self.logo_label)
        
        # Buttons frame
        self.buttons_frame = QFrame()
        self.buttons_frame.setFrameShape(QFrame.StyledPanel)
        self.buttons_layout = QVBoxLayout(self.buttons_frame)
        
        # Buttons
        self.create_button("Start I2P Router", self.start_router)
        self.create_button("Stop I2P Router", self.stop_router)
        self.create_button("Graceful Stop", self.graceful_stop)
        self.create_button("Restart I2P Router", self.restart_router)
        self.create_button("Check I2P Status", self.check_status)
        self.create_button("Install I2P (Auto-Start)", self.install_i2p)
        self.create_button("Remove I2P (Disable Auto-Start)", self.remove_i2p)
        self.create_button("View Thread Dump", self.view_thread_dump)
        self.create_button("About", self.show_about)
        
        self.main_layout.addWidget(self.buttons_frame)
        
        # Exit button
        self.exit_button = QPushButton("Exit")
        self.exit_button.clicked.connect(self.close)
        self.exit_button.setStyleSheet("""
            QPushButton {
                background-color: #2B2B2B;
                color: #FFD700;
                border: 1px solid #FFD700;
                border-radius: 5px;
                padding: 10px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3B3B3B;
                border: 1px solid #FFE5B4;
            }
        """)
        self.main_layout.addWidget(self.exit_button)
        
        # Apply dark theme
        self.apply_dark_theme()
    
    def create_button(self, text, slot):
        button = QPushButton(text)
        button.clicked.connect(slot)
        button.setStyleSheet("""
            QPushButton {
                background-color: #2B2B2B;
                color: #FFD700;
                border: 1px solid #FFD700;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
                text-align: left;
                padding-left: 20px;
            }
            QPushButton:hover {
                background-color: #3B3B3B;
            }
        """)
        self.buttons_layout.addWidget(button)
        return button
    
    def apply_dark_theme(self):
        # Dark theme colors
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, QColor(255, 215, 0))  # Golden text
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ToolTipText, QColor(255, 215, 0))
        dark_palette.setColor(QPalette.Text, QColor(255, 215, 0))
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, QColor(255, 215, 0))
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        self.setPalette(dark_palette)
        
        # Stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1E1E1E;
            }
            QLabel {
                color: #FFD700;
            }
            QFrame {
                background-color: #2B2B2B;
                border-radius: 10px;
            }
            QStatusBar {
                color: #FFD700;
                background-color: #1E1E1E;
            }
        """)
    
    def run_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            return "", str(e), 1
    
    def show_output(self, title, output, error=""):
        dialog = QMessageBox(self)
        dialog.setWindowTitle(title)
        dialog.setIcon(QMessageBox.Information)
        
        message = output
        if error:
            message += f"\n\nError:\n{error}"
        
        dialog.setText(message)
        dialog.setStyleSheet("""
            QMessageBox {
                background-color: #2B2B2B;
            }
            QMessageBox QLabel {
                color: #FFD700;
            }
            QPushButton {
                background-color: #2B2B2B;
                color: #FFD700;
                border: 1px solid #FFD700;
                border-radius: 5px;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #3B3B3B;
            }
        """)
        dialog.exec_()
    
    def start_router(self):
        output, error, code = self.run_command("i2prouter start")
        if code == 0:
            self.show_output("I2P Router Started", "I2P Router has been successfully started.")
        else:
            self.show_output("Error", "Failed to start I2P Router.", error)
    
    def stop_router(self):
        output, error, code = self.run_command("i2prouter stop")
        if code == 0:
            self.show_output("I2P Router Stopped", "I2P Router has been successfully stopped.")
        else:
            self.show_output("Error", "Failed to stop I2P Router.", error)
    
    def graceful_stop(self):
        output, error, code = self.run_command("i2prouter graceful")
        if code == 0:
            self.show_output("I2P Router Gracefully Stopped", "I2P Router has been gracefully stopped.")
        else:
            self.show_output("Error", "Failed to gracefully stop I2P Router.", error)
    
    def restart_router(self):
        output, error, code = self.run_command("i2prouter restart")
        if code == 0:
            self.show_output("I2P Router Restarted", "I2P Router has been successfully restarted.")
        else:
            self.show_output("Error", "Failed to restart I2P Router.", error)
    
    def check_status(self):
        output, error, code = self.run_command("i2prouter status")
        if code == 0:
            self.show_output("I2P Router Status", output)
        else:
            self.show_output("I2P Router Status", "You are not connected to the I2P network")
    
    def install_i2p(self):
        output, error, code = self.run_command("i2prouter install")
        if code == 0:
            self.show_output("I2P Installed", "I2P has been successfully installed and auto-start has been enabled.")
        else:
            self.show_output("Error", "Failed to install I2P.", error)
    
    def remove_i2p(self):
        output, error, code = self.run_command("i2prouter remove")
        if code == 0:
            self.show_output("I2P Removed", "I2P has been successfully removed and auto-start has been disabled.")
        else:
            self.show_output("Error", "Failed to remove I2P.", error)
    
    def view_thread_dump(self):
        output, error, code = self.run_command("i2prouter dump")
        if code == 0:
            self.show_output("Thread Dump", output)
        else:
            self.show_output("Error", "Failed to view thread dump.", error)
    
    def show_about(self):
        about_text = """
        <h2>I2P - Invisible Internet Project</h2>
        <p>I2P is a network protocol that provides anonymous and secure communication.</p>
        <p><b>Menu Options:</b></p>
        <ul>
            <li><b>Start:</b> Launches I2P Router as a daemon.</li>
            <li><b>Stop:</b> Terminates I2P process.</li>
            <li><b>Graceful Stop:</b> Stops I2P, may take up to 11 minutes.</li>
            <li><b>Restart:</b> Stops and starts I2P again.</li>
            <li><b>Status:</b> Shows whether I2P is running.</li>
            <li><b>Install:</b> Enables I2P auto-start on boot.</li>
            <li><b>Remove:</b> Disables I2P auto-start.</li>
            <li><b>Thread Dump:</b> Shows Java thread dump.</li>
        </ul>
        """
        
        about_dialog = QMessageBox(self)
        about_dialog.setWindowTitle("About")
        about_dialog.setTextFormat(Qt.RichText)
        about_dialog.setText(about_text)
        about_dialog.setStyleSheet("""
            QMessageBox {
                background-color: #2B2B2B;
            }
            QMessageBox QLabel {
                color: #FFD700;
            }
            QPushButton {
                background-color: #2B2B2B;
                color: #FFD700;
                border: 1px solid #FFD700;
                border-radius: 5px;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #3B3B3B;
            }
        """)
        about_dialog.exec_()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = I2PRouterMenu()
    window.show()
    sys.exit(app.exec_())
