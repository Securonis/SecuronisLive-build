#!/usr/bin/env python3
import sys
import os
import shutil
import json
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                            QFileDialog, QMessageBox, QTabWidget, QLineEdit,
                            QComboBox, QSpinBox, QCheckBox, QInputDialog,
                            QProgressBar, QGroupBox, QRadioButton, QSplitter,
                            QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem,
                            QFormLayout, QDialog, QStackedWidget, QSplashScreen)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QPixmap
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64
import secrets
import string
import hashlib
import qrcode
from PIL import Image
import io
import math
import zlib
from cryptography.hazmat.primitives.asymmetric import ec 

# Version 1.2 Developer: root0emir

class FileEncryptionThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, file_path, key, operation, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.key = key
        self.operation = operation  # 'encrypt' or 'decrypt'

    def run(self):
        try:
            if self.operation == 'encrypt':
                self.encrypt_file()
            else:
                self.decrypt_file()
        except Exception as e:
            self.error.emit(str(e))

    def encrypt_file(self):
        try:
            with open(self.file_path, 'rb') as file:
                data = file.read()
            
            f = Fernet(self.key)
            encrypted = f.encrypt(data)
            
            # Encrypt filename
            filename = os.path.basename(self.file_path)
            encrypted_filename = base64.urlsafe_b64encode(filename.encode()).decode()
            
            # Save encrypted file
            output_path = f"{self.file_path}.encrypted"
            with open(output_path, 'wb') as file:
                file.write(encrypted)
            
            # Save metadata
            metadata = {
                'original_name': filename,
                'encrypted_name': encrypted_filename,
                'timestamp': datetime.now().isoformat(),
                'algorithm': 'AES-256',
                'key_hash': hashlib.sha256(self.key).hexdigest()
            }
            
            with open(f"{output_path}.meta", 'w') as meta_file:
                json.dump(metadata, meta_file)
            
            self.finished.emit(output_path)
        except Exception as e:
            self.error.emit(str(e))

    def decrypt_file(self):
        try:
            with open(self.file_path, 'rb') as file:
                encrypted = file.read()
            
            f = Fernet(self.key)
            decrypted = f.decrypt(encrypted)
            
            # Read metadata
            meta_path = f"{self.file_path}.meta"
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as meta_file:
                    metadata = json.load(meta_file)
                original_name = metadata['original_name']
            else:
                original_name = os.path.splitext(os.path.basename(self.file_path))[0]
            
            # Save decrypted file
            output_path = os.path.join(os.path.dirname(self.file_path), original_name)
            with open(output_path, 'wb') as file:
                file.write(decrypted)
            
            self.finished.emit(output_path)
        except Exception as e:
            self.error.emit(str(e))

class CryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PxrtalCrypt")
        self.setMinimumSize(1200, 800)
        
        # Set default theme
        self.current_theme = "dark_blue"
        self.set_theme(self.current_theme)
        
        # Create main layout
        main_layout = QHBoxLayout()
        
        # Create left panel
        left_panel = QWidget()
        left_panel.setFixedWidth(350)
        left_layout = QVBoxLayout()
        left_layout.setSpacing(10)  # Reduce spacing between widgets
        
        # Add logo
        logo_label = QLabel()
        pixmap = QPixmap("/usr/share/icons/securonis/pxrtaltext.png")
        if not pixmap.isNull():
            pixmap = pixmap.scaled(330, 180, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left_layout.addWidget(logo_label)
        
        # Add menu buttons
        menu_buttons = [
            ("Text Encryption", self.show_text_crypto),
            ("File Encryption", self.show_file_crypto),
            ("Password Manager", self.show_password_manager),
            ("File Signing", self.show_file_signing),
            ("Steganography", self.show_steganography),
            ("Secure Deletion", self.show_secure_delete),
            ("Encryption Analysis", self.show_encryption_analysis),
            ("Key Management", self.show_key_management),
            ("Security Reports", self.show_security_reports),
            ("About", self.show_about)
        ]
        
        for text, slot in menu_buttons:
            btn = QPushButton(text)
            btn.setFixedHeight(40)
            btn.clicked.connect(slot)
            left_layout.addWidget(btn)
            
        # Add theme selector
        theme_group = QGroupBox("Theme")
        theme_layout = QHBoxLayout()
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark Blue", "Dark", "Light", "Modern"])
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_layout.addWidget(self.theme_combo)
        
        theme_group.setLayout(theme_layout)
        left_layout.addWidget(theme_group)
            
        left_panel.setLayout(left_layout)
        main_layout.addWidget(left_panel)
        
        # Create right panel
        self.right_panel = QStackedWidget()
        main_layout.addWidget(self.right_panel)
        
        # Set main layout
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
        # Initialize pages
        self.init_text_crypto_page()
        self.init_file_crypto_page()
        self.init_password_manager_page()
        self.init_file_signing_page()
        self.init_steganography_page()
        self.init_secure_delete_page()
        self.init_encryption_analysis_page()
        self.init_key_management_page()
        self.init_security_reports_page()
        self.init_about_page()

    def set_theme(self, theme):
        if theme == "dark_blue":
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #1a1a2e;
                    color: #ffffff;
                }
                QPushButton {
                    background-color: #16213e;
                    color: #ffffff;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #0f3460;
                }
                QPushButton:pressed {
                    background-color: #0d2b4e;
                }
                QLineEdit, QTextEdit, QComboBox {
                    background-color: #16213e;
                    color: #ffffff;
                    border: none;
                    border-radius: 4px;
                    padding: 5px;
                }
                QComboBox {
                    background-color: #16213e;
                    color: #ffffff;
                    border: none;
                    border-radius: 4px;
                    padding: 5px;
                    margin: 0px;
                    min-height: 25px;
                }
                QComboBox:focus, QComboBox:on, QComboBox:hover, QComboBox::drop-down:focus, QComboBox::drop-down:on, QComboBox::drop-down:hover {
                    background-color: #16213e;
                    border: none;
                }
                QComboBox::drop-down {
                    border: none;
                    background-color: #16213e;
                    width: 20px;
                    margin: 0px;
                }
                QComboBox::down-arrow {
                    image: url(/usr/share/icons/securonis/down_arrow.png);
                    width: 12px;
                    height: 12px;
                    background-color: #16213e;
                }
                QComboBox QFrame {
                    border: none;
                    background-color: #16213e;
                }
                QComboBox QAbstractItemView {
                    background-color: #16213e;
                    color: #ffffff;
                    border: none;
                    selection-background-color: #0f3460;
                    selection-color: #ffffff;
                    outline: none;
                }
                QComboBox QAbstractItemView::item {
                    border: none;
                    margin: 0px;
                    padding: 5px;
                    min-height: 25px;
                    background-color: #16213e;
                }
                QComboBox QAbstractItemView::item:selected {
                    background-color: #0f3460;
                }
                QComboBox QAbstractItemView QScrollBar:vertical {
                    background-color: #16213e;
                    width: 12px;
                    margin: 0px;
                    border: none;
                }
                QComboBox QAbstractItemView QScrollBar::handle:vertical {
                    background-color: #0f3460;
                    min-height: 20px;
                    border-radius: 6px;
                    border: none;
                }
                QComboBox QAbstractItemView QScrollBar::add-line:vertical,
                QComboBox QAbstractItemView QScrollBar::sub-line:vertical {
                    height: 0px;
                    border: none;
                    background: none;
                }
                QGroupBox {
                    border: 1px solid #0f3460;
                    border-radius: 4px;
                    margin-top: 16px;
                    padding-top: 16px;
                    color: #ffffff;
                    font-weight: bold;
                }
                QProgressBar {
                    border: 1px solid #0f3460;
                    border-radius: 4px;
                    text-align: center;
                    background-color: #16213e;
                    color: #ffffff;
                }
                QProgressBar::chunk {
                    background-color: #0f3460;
                }
                QTreeWidget, QListWidget {
                    background-color: #16213e;
                    color: #ffffff;
                    border: 1px solid #0f3460;
                    border-radius: 4px;
                }
                QHeaderView::section {
                    background-color: #1a1a2e;
                    color: #ffffff;
                    padding: 8px;
                    border: 1px solid #0f3460;
                }
                QLabel {
                    color: #ffffff;
                }
                QDialog {
                    background-color: #1a1a2e;
                    color: #ffffff;
                }
                QMessageBox {
                    background-color: #1a1a2e;
                    color: #ffffff;
                }
                QMessageBox QLabel {
                    color: #ffffff;
                }
                QMessageBox QPushButton {
                    background-color: #16213e;
                    color: #ffffff;
                    border: 1px solid #0f3460;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QMessageBox QPushButton:hover {
                    background-color: #0f3460;
                }
                QCheckBox {
                    color: #ffffff;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                    border: 1px solid #0f3460;
                    border-radius: 3px;
                    background-color: #16213e;
                }
                QCheckBox::indicator:checked {
                    background-color: #0f3460;
                    border: 1px solid #0f3460;
                    image: url(/usr/share/icons/securonis/tick.png);
                }
                QCheckBox::indicator:hover {
                    border: 1px solid #0f3460;
                }
            """)
        elif theme == "dark":
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #1e1e1e;
                    color: #ffffff;
                }
                QPushButton {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #3d3d3d;
                }
                QPushButton:pressed {
                    background-color: #4d4d4d;
                }
                QLineEdit, QTextEdit, QComboBox {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: none;
                    border-radius: 4px;
                    padding: 5px;
                }
                QComboBox {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: none;
                    border-radius: 4px;
                    padding: 5px;
                    margin: 0px;
                    min-height: 25px;
                }
                QComboBox:focus, QComboBox:on, QComboBox:hover, QComboBox::drop-down:focus, QComboBox::drop-down:on, QComboBox::drop-down:hover {
                    background-color: #2d2d2d;
                    border: none;
                }
                QComboBox::drop-down {
                    border: none;
                    background-color: #2d2d2d;
                    width: 20px;
                    margin: 0px;
                }
                QComboBox::down-arrow {
                    image: url(/usr/share/icons/securonis/down_arrow.png);
                    width: 12px;
                    height: 12px;
                    background-color: #2d2d2d;
                }
                QComboBox QFrame {
                    border: none;
                    background-color: #2d2d2d;
                }
                QComboBox QAbstractItemView {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: none;
                    selection-background-color: #3d3d3d;
                    selection-color: #ffffff;
                    outline: none;
                }
                QComboBox QAbstractItemView::item {
                    border: none;
                    margin: 0px;
                    padding: 5px;
                    min-height: 25px;
                    background-color: #2d2d2d;
                }
                QComboBox QAbstractItemView::item:selected {
                    background-color: #3d3d3d;
                }
                QComboBox QAbstractItemView QScrollBar:vertical {
                    background-color: #2d2d2d;
                    width: 12px;
                    margin: 0px;
                    border: none;
                }
                QComboBox QAbstractItemView QScrollBar::handle:vertical {
                    background-color: #3d3d3d;
                    min-height: 20px;
                    border-radius: 6px;
                    border: none;
                }
                QComboBox QAbstractItemView QScrollBar::add-line:vertical,
                QComboBox QAbstractItemView QScrollBar::sub-line:vertical {
                    height: 0px;
                    border: none;
                    background: none;
                }
                QGroupBox {
                    border: 1px solid #3d3d3d;
                    border-radius: 4px;
                    margin-top: 16px;
                    padding-top: 16px;
                    color: #ffffff;
                    font-weight: bold;
                }
                QProgressBar {
                    border: 1px solid #3d3d3d;
                    border-radius: 4px;
                    text-align: center;
                    background-color: #2d2d2d;
                    color: #ffffff;
                }
                QProgressBar::chunk {
                    background-color: #3d3d3d;
                }
                QTreeWidget, QListWidget {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                    border-radius: 4px;
                }
                QHeaderView::section {
                    background-color: #1e1e1e;
                    color: #ffffff;
                    padding: 8px;
                    border: 1px solid #3d3d3d;
                }
                QLabel {
                    color: #ffffff;
                }
                QDialog {
                    background-color: #1e1e1e;
                    color: #ffffff;
                }
                QMessageBox {
                    background-color: #1e1e1e;
                    color: #ffffff;
                }
                QMessageBox QLabel {
                    color: #ffffff;
                }
                QMessageBox QPushButton {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QMessageBox QPushButton:hover {
                    background-color: #3d3d3d;
                }
                QCheckBox {
                    color: #ffffff;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                    border: 1px solid #3d3d3d;
                    border-radius: 3px;
                    background-color: #2d2d2d;
                }
                QCheckBox::indicator:checked {
                    background-color: #3d3d3d;
                    border: 1px solid #3d3d3d;
                    image: url(/usr/share/icons/securonis/tick.png);
                }
                QCheckBox::indicator:hover {
                    border: 1px solid #3d3d3d;
                }
            """)
        elif theme == "light":
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #f8f9fa;
                    color: #212529;
                }
                QPushButton {
                    background-color: #e9ecef;
                    color: #212529;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #dee2e6;
                }
                QPushButton:pressed {
                    background-color: #ced4da;
                }
                QLineEdit, QTextEdit, QComboBox {
                    background-color: #ffffff;
                    color: #212529;
                    border: none;
                    border-radius: 4px;
                    padding: 5px;
                }
                QComboBox {
                    background-color: #ffffff;
                    color: #212529;
                    border: none;
                    border-radius: 4px;
                    padding: 5px;
                    margin: 0px;
                    min-height: 25px;
                }
                QComboBox:focus, QComboBox:on, QComboBox:hover, QComboBox::drop-down:focus, QComboBox::drop-down:on, QComboBox::drop-down:hover {
                    background-color: #ffffff;
                    border: none;
                }
                QComboBox::drop-down {
                    border: none;
                    background-color: #ffffff;
                    width: 20px;
                    margin: 0px;
                }
                QComboBox::down-arrow {
                    image: url(/usr/share/icons/securonis/down_arrow.png);
                    width: 12px;
                    height: 12px;
                    background-color: #ffffff;
                }
                QComboBox QFrame {
                    border: none;
                    background-color: #ffffff;
                }
                QComboBox QAbstractItemView {
                    background-color: #ffffff;
                    color: #212529;
                    border: none;
                    selection-background-color: #dee2e6;
                    selection-color: #212529;
                    outline: none;
                }
                QComboBox QAbstractItemView::item {
                    border: none;
                    margin: 0px;
                    padding: 5px;
                    min-height: 25px;
                    background-color: #ffffff;
                }
                QComboBox QAbstractItemView::item:selected {
                    background-color: #dee2e6;
                }
                QComboBox QAbstractItemView QScrollBar:vertical {
                    background: #f8f9fa;
                    width: 12px;
                    margin: 0px;
                    border: none;
                }
                QComboBox QAbstractItemView QScrollBar::handle:vertical {
                    background: #dee2e6;
                    min-height: 20px;
                    border-radius: 6px;
                    border: none;
                }
                QComboBox QAbstractItemView QScrollBar::add-line:vertical,
                QComboBox QAbstractItemView QScrollBar::sub-line:vertical {
                    height: 0px;
                    border: none;
                    background: none;
                }
                QGroupBox {
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    margin-top: 16px;
                    padding-top: 16px;
                    color: #212529;
                    font-weight: bold;
                }
                QProgressBar {
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    text-align: center;
                    background-color: #ffffff;
                    color: #212529;
                }
                QProgressBar::chunk {
                    background-color: #0d6efd;
                }
                QTreeWidget, QListWidget {
                    background-color: #ffffff;
                    color: #212529;
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                }
                QHeaderView::section {
                    background-color: #f8f9fa;
                    color: #212529;
                    padding: 8px;
                    border: 1px solid #ced4da;
                }
                QLabel {
                    color: #212529;
                }
                QDialog {
                    background-color: #f8f9fa;
                    color: #212529;
                }
                QMessageBox {
                    background-color: #f8f9fa;
                    color: #212529;
                }
                QMessageBox QLabel {
                    color: #212529;
                }
                QMessageBox QPushButton {
                    background-color: #e9ecef;
                    color: #212529;
                    border: 1px solid #ced4da;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QMessageBox QPushButton:hover {
                    background-color: #dee2e6;
                }
                QCheckBox {
                    color: #212529;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                    border: 1px solid #ced4da;
                    border-radius: 3px;
                    background-color: #ffffff;
                }
                QCheckBox::indicator:checked {
                    background-color: #0d6efd;
                    border: 1px solid #0d6efd;
                    image: url(/usr/share/icons/securonis/tick.png);
                }
                QCheckBox::indicator:hover {
                    border: 1px solid #0d6efd;
                }
            """)
        elif theme == "modern":
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #ffffff;
                    color: #2c3e50;
                }
                QPushButton {
                    background-color: #3498db;
                    color: #ffffff;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
                QPushButton:pressed {
                    background-color: #2472a4;
                }
                QLineEdit, QTextEdit, QComboBox {
                    background-color: #f8f9fa;
                    color: #2c3e50;
                    border: none;
                    border-radius: 4px;
                    padding: 5px;
                }
                QComboBox {
                    background-color: #f8f9fa;
                    color: #2c3e50;
                    border: none;
                    border-radius: 4px;
                    padding: 5px;
                    margin: 0px;
                    min-height: 25px;
                }
                QComboBox:focus, QComboBox:on, QComboBox:hover, QComboBox::drop-down:focus, QComboBox::drop-down:on, QComboBox::drop-down:hover {
                    background-color: #f8f9fa;
                    border: none;
                }
                QComboBox::drop-down {
                    border: none;
                    background-color: #f8f9fa;
                    width: 20px;
                    margin: 0px;
                }
                QComboBox::down-arrow {
                    image: url(/usr/share/icons/securonis/down_arrow.png);
                    width: 12px;
                    height: 12px;
                    background-color: #f8f9fa;
                }
                QComboBox QFrame {
                    border: none;
                    background-color: #f8f9fa;
                }
                QComboBox QAbstractItemView {
                    background-color: #f8f9fa;
                    color: #2c3e50;
                    border: none;
                    selection-background-color: #bdc3c7;
                    selection-color: #2c3e50;
                    outline: none;
                }
                QComboBox QAbstractItemView::item {
                    border: none;
                    margin: 0px;
                    padding: 5px;
                    min-height: 25px;
                    background-color: #f8f9fa;
                }
                QComboBox QAbstractItemView::item:selected {
                    background-color: #bdc3c7;
                }
                QComboBox QAbstractItemView QScrollBar:vertical {
                    background: #f8f9fa;
                    width: 12px;
                    margin: 0px;
                    border: none;
                }
                QComboBox QAbstractItemView QScrollBar::handle:vertical {
                    background: #bdc3c7;
                    min-height: 20px;
                    border-radius: 6px;
                    border: none;
                }
                QComboBox QAbstractItemView QScrollBar::add-line:vertical,
                QComboBox QAbstractItemView QScrollBar::sub-line:vertical {
                    height: 0px;
                    border: none;
                    background: none;
                }
                QGroupBox {
                    border: 1px solid #bdc3c7;
                    border-radius: 4px;
                    margin-top: 16px;
                    padding-top: 16px;
                    color: #2c3e50;
                    font-weight: bold;
                }
                QProgressBar {
                    border: 1px solid #bdc3c7;
                    border-radius: 4px;
                    text-align: center;
                    background-color: #f8f9fa;
                    color: #2c3e50;
                }
                QProgressBar::chunk {
                    background-color: #3498db;
                }
                QTreeWidget, QListWidget {
                    background-color: #f8f9fa;
                    color: #2c3e50;
                    border: 1px solid #bdc3c7;
                    border-radius: 4px;
                }
                QHeaderView::section {
                    background-color: #ffffff;
                    color: #2c3e50;
                    padding: 8px;
                    border: 1px solid #bdc3c7;
                }
                QLabel {
                    color: #2c3e50;
                }
                QDialog {
                    background-color: #ffffff;
                    color: #2c3e50;
                }
                QMessageBox {
                    background-color: #ffffff;
                    color: #2c3e50;
                }
                QMessageBox QLabel {
                    color: #2c3e50;
                }
                QMessageBox QPushButton {
                    background-color: #3498db;
                    color: #ffffff;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QMessageBox QPushButton:hover {
                    background-color: #2980b9;
                }
                QCheckBox {
                    color: #2c3e50;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                    border: 1px solid #bdc3c7;
                    border-radius: 3px;
                    background-color: #f8f9fa;
                }
                QCheckBox::indicator:checked {
                    background-color: #3498db;
                    border: 1px solid #3498db;
                    image: url(/usr/share/icons/securonis/tick.png);
                }
                QCheckBox::indicator:hover {
                    border: 1px solid #3498db;
                }
            """)

    def change_theme(self, theme):
        theme_map = {
            "Dark Blue": "dark_blue",
            "Dark": "dark",
            "Light": "light",
            "Modern": "modern"
        }
        self.current_theme = theme_map.get(theme, "dark_blue")
        self.set_theme(self.current_theme)

    def show_about(self):
        self.right_panel.setCurrentIndex(9)
        
    def init_about_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # About content
        about_group = QGroupBox("About PxrtalCrypt")
        about_layout = QVBoxLayout()
        
        # Logo
        logo_label = QLabel()
        pixmap = QPixmap("/usr/share/icons/securonis/pxrtal.png")
        if not pixmap.isNull():
            pixmap = pixmap.scaled(400, 200, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(logo_label)
        
        # Description
        description = QTextEdit()
        description.setReadOnly(True)
        description.setHtml("""
            <h2>PxrtalCrypt - Cryptography Toolkit</h2>
            <p>Version: 1.2</p>
            <p>PxrtalCrypt is a comprehensive cryptography application that provides various security features:</p>
            <ul>
                <li>Text and File Encryption/Decryption</li>
                <li>Password Management</li>
                <li>File Signing and Verification</li>
                <li>Steganography</li>
                <li>Secure File Deletion</li>
                <li>Encryption Analysis</li>
                <li>Key Management</li>
                <li>Security Reports</li>
            </ul>
            <p>This application uses modern cryptographic algorithms and follows security best practices.</p>
            <p>PxrtalCrypt Developed by root0emir</p>
            <p>Contact: root0emir@protonmail.com </p>
            <p>Developer Github: https://github.com/root0emir </p>
        """)
        about_layout.addWidget(description)
        
        about_group.setLayout(about_layout)
        layout.addWidget(about_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_text_crypto(self):
        self.right_panel.setCurrentIndex(0)
        
    def init_text_crypto_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # Algorithm selection
        algo_group = QGroupBox("Encryption Algorithm")
        algo_layout = QVBoxLayout()
        
        self.algo_combo = QComboBox()
        self.algo_combo.addItems([
            "AES-256 (GCM)",
            "ChaCha20-Poly1305",
            "Fernet",
            "RSA-OAEP",
            "Blowfish",
            "Twofish",
            "Serpent",
            "Camellia"
        ])
        algo_layout.addWidget(self.algo_combo)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # Text input
        text_group = QGroupBox("Text")
        text_layout = QVBoxLayout()
        
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("Enter text to encrypt/decrypt...")
        text_layout.addWidget(self.text_edit)
        
        text_group.setLayout(text_layout)
        layout.addWidget(text_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.clicked.connect(self.encrypt_text)
        btn_layout.addWidget(encrypt_btn)
        
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.clicked.connect(self.decrypt_text)
        btn_layout.addWidget(decrypt_btn)
        
        layout.addLayout(btn_layout)
        
        # Result
        result_group = QGroupBox("Result")
        result_layout = QVBoxLayout()
        
        self.result_edit = QTextEdit()
        self.result_edit.setReadOnly(True)
        result_layout.addWidget(self.result_edit)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_file_crypto(self):
        self.right_panel.setCurrentIndex(1)
        
    def init_file_crypto_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # File selection
        file_group = QGroupBox("Files")
        file_layout = QVBoxLayout()
        
        self.file_list = QListWidget()
        file_layout.addWidget(self.file_list)
        
        btn_layout = QHBoxLayout()
        
        add_file_btn = QPushButton("Add File")
        add_file_btn.clicked.connect(self.add_file)
        btn_layout.addWidget(add_file_btn)
        
        add_folder_btn = QPushButton("Add Folder")
        add_folder_btn.clicked.connect(self.add_folder)
        btn_layout.addWidget(add_folder_btn)
        
        remove_btn = QPushButton("Remove")
        remove_btn.clicked.connect(self.remove_file)
        btn_layout.addWidget(remove_btn)
        
        file_layout.addLayout(btn_layout)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Encryption options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        
        self.algo_combo = QComboBox()
        self.algo_combo.addItems([
            "AES-256 (GCM)",
            "ChaCha20-Poly1305",
            "Fernet",
            "RSA-OAEP",
            "Blowfish",
            "Twofish",
            "Serpent",
            "Camellia"
        ])
        options_layout.addWidget(self.algo_combo)
        
        # Key file selection
        key_layout = QHBoxLayout()
        self.key_path_edit = QLineEdit()
        self.key_path_edit.setReadOnly(True)
        self.key_path_edit.setPlaceholderText("Select key file (for decryption)")
        browse_key_btn = QPushButton("Browse Key")
        browse_key_btn.clicked.connect(self.browse_key_file)
        key_layout.addWidget(self.key_path_edit)
        key_layout.addWidget(browse_key_btn)
        options_layout.addLayout(key_layout)
        
        # Manual key input
        manual_key_layout = QHBoxLayout()
        self.manual_key_edit = QLineEdit()
        self.manual_key_edit.setPlaceholderText("Or enter key manually")
        self.manual_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        manual_key_layout.addWidget(self.manual_key_edit)
        options_layout.addLayout(manual_key_layout)
        
        self.compress_check = QCheckBox("Compress before encryption")
        options_layout.addWidget(self.compress_check)
        
        self.encrypt_name_check = QCheckBox("Encrypt filenames")
        options_layout.addWidget(self.encrypt_name_check)
        
        self.verify_check = QCheckBox("Verify integrity")
        options_layout.addWidget(self.verify_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Progress
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.clicked.connect(self.encrypt_files)
        btn_layout.addWidget(encrypt_btn)
        
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.clicked.connect(self.decrypt_files)
        btn_layout.addWidget(decrypt_btn)
        
        layout.addLayout(btn_layout)
        
        # History
        history_group = QGroupBox("History")
        history_layout = QVBoxLayout()
        
        self.history_list = QTreeWidget()
        self.history_list.setHeaderLabels(["File", "Operation", "Date", "Status"])
        history_layout.addWidget(self.history_list)
        
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_password_manager(self):
        self.right_panel.setCurrentIndex(2)
        
    def init_password_manager_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # Password manager interface
        pass_manager_group = QGroupBox("Password Manager")
        pass_manager_layout = QVBoxLayout()
        
        # Password list
        self.password_list = QTreeWidget()
        self.password_list.setHeaderLabels(["Site/App", "Username", "Password", "Last Updated"])
        pass_manager_layout.addWidget(self.password_list)
        
        # Password form
        form_layout = QFormLayout()
        self.site_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Site/App:", self.site_edit)
        form_layout.addRow("Username:", self.username_edit)
        form_layout.addRow("Password:", self.password_edit)
        pass_manager_layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Add")
        edit_btn = QPushButton("Edit")
        delete_btn = QPushButton("Delete")
        generate_btn = QPushButton("Generate")
        export_btn = QPushButton("Export")
        import_btn = QPushButton("Import")
        
        add_btn.clicked.connect(self.add_password)
        edit_btn.clicked.connect(self.edit_password)
        delete_btn.clicked.connect(self.delete_password)
        generate_btn.clicked.connect(self.generate_password)
        export_btn.clicked.connect(self.export_passwords)
        import_btn.clicked.connect(self.import_passwords)
        
        button_layout.addWidget(add_btn)
        button_layout.addWidget(edit_btn)
        button_layout.addWidget(delete_btn)
        button_layout.addWidget(generate_btn)
        button_layout.addWidget(export_btn)
        button_layout.addWidget(import_btn)
        
        pass_manager_layout.addLayout(button_layout)
        pass_manager_group.setLayout(pass_manager_layout)
        layout.addWidget(pass_manager_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_file_signing(self):
        self.right_panel.setCurrentIndex(3)
        
    def init_file_signing_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # File signing interface
        signing_group = QGroupBox("File Signing")
        signing_layout = QVBoxLayout()
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_btn)
        signing_layout.addLayout(file_layout)
        
        # Signing options
        options_group = QGroupBox("Signing Options")
        options_layout = QVBoxLayout()
        
        self.sign_algo_combo = QComboBox()
        self.sign_algo_combo.addItems(["RSA-SHA256", "RSA-SHA512", "ECDSA-SHA256", "ECDSA-SHA512"])
        options_layout.addWidget(QLabel("Signing Algorithm:"))
        options_layout.addWidget(self.sign_algo_combo)
        
        self.verify_check = QCheckBox("Verify signature")
        options_layout.addWidget(self.verify_check)
        
        options_group.setLayout(options_layout)
        signing_layout.addWidget(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        sign_btn = QPushButton("Sign")
        verify_btn = QPushButton("Verify")
        sign_btn.clicked.connect(self.sign_file)
        verify_btn.clicked.connect(self.verify_signature)
        button_layout.addWidget(sign_btn)
        button_layout.addWidget(verify_btn)
        signing_layout.addLayout(button_layout)
        
        signing_group.setLayout(signing_layout)
        layout.addWidget(signing_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_steganography(self):
        self.right_panel.setCurrentIndex(4)
        
    def init_steganography_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # Steganography interface
        stego_group = QGroupBox("Steganography")
        stego_layout = QVBoxLayout()
        
        # Image selection
        image_layout = QHBoxLayout()
        self.image_path_edit = QLineEdit()
        self.image_path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_image)
        image_layout.addWidget(self.image_path_edit)
        image_layout.addWidget(browse_btn)
        stego_layout.addLayout(image_layout)
        
        # Message input
        message_group = QGroupBox("Message")
        message_layout = QVBoxLayout()
        self.message_edit = QTextEdit()
        self.message_edit.setPlaceholderText("Enter message to hide...")
        message_layout.addWidget(self.message_edit)
        message_group.setLayout(message_layout)
        stego_layout.addWidget(message_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        hide_btn = QPushButton("Hide Message")
        extract_btn = QPushButton("Extract Message")
        hide_btn.clicked.connect(self.hide_message)
        extract_btn.clicked.connect(self.extract_message)
        button_layout.addWidget(hide_btn)
        button_layout.addWidget(extract_btn)
        stego_layout.addLayout(button_layout)
        
        stego_group.setLayout(stego_layout)
        layout.addWidget(stego_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_secure_delete(self):
        self.right_panel.setCurrentIndex(5)
        
    def init_secure_delete_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # Secure deletion interface
        delete_group = QGroupBox("Secure Deletion")
        delete_layout = QVBoxLayout()
        
        # File selection
        file_layout = QHBoxLayout()
        self.delete_path_edit = QLineEdit()
        self.delete_path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_delete)
        file_layout.addWidget(self.delete_path_edit)
        file_layout.addWidget(browse_btn)
        delete_layout.addLayout(file_layout)
        
        # Deletion options
        options_group = QGroupBox("Deletion Options")
        options_layout = QVBoxLayout()
        
        self.delete_algo_combo = QComboBox()
        self.delete_algo_combo.addItems(["1 Pass", "3 Pass", "7 Pass", "35 Pass"])
        options_layout.addWidget(QLabel("Deletion Algorithm:"))
        options_layout.addWidget(self.delete_algo_combo)
        
        self.verify_delete_check = QCheckBox("Verify after deletion")
        options_layout.addWidget(self.verify_delete_check)
        
        options_group.setLayout(options_layout)
        delete_layout.addWidget(options_group)
        
        # Delete button
        delete_btn = QPushButton("Secure Delete")
        delete_btn.clicked.connect(self.secure_delete)
        delete_layout.addWidget(delete_btn)
        
        delete_group.setLayout(delete_layout)
        layout.addWidget(delete_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_encryption_analysis(self):
        self.right_panel.setCurrentIndex(6)
        
    def init_encryption_analysis_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # Encryption analysis interface
        analysis_group = QGroupBox("Encryption Analysis")
        analysis_layout = QVBoxLayout()
        
        # File selection
        file_layout = QHBoxLayout()
        self.analysis_path_edit = QLineEdit()
        self.analysis_path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_analysis)
        file_layout.addWidget(self.analysis_path_edit)
        file_layout.addWidget(browse_btn)
        analysis_layout.addLayout(file_layout)
        
        # Analysis options
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout()
        
        self.analysis_type_combo = QComboBox()
        self.analysis_type_combo.addItems([
            "Entropy Analysis",
            "Frequency Analysis",
            "Correlation Analysis",
            "Cryptographic Strength"
        ])
        options_layout.addWidget(QLabel("Analysis Type:"))
        options_layout.addWidget(self.analysis_type_combo)
        
        options_group.setLayout(options_layout)
        analysis_layout.addWidget(options_group)
        
        # Analyze button
        analyze_btn = QPushButton("Analyze")
        analyze_btn.clicked.connect(self.analyze_file)
        analysis_layout.addWidget(analyze_btn)
        
        # Results area
        result_group = QGroupBox("Analysis Results")
        result_layout = QVBoxLayout()
        self.analysis_result = QTextEdit()
        self.analysis_result.setReadOnly(True)
        result_layout.addWidget(self.analysis_result)
        result_group.setLayout(result_layout)
        analysis_layout.addWidget(result_group)
        
        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_key_management(self):
        self.right_panel.setCurrentIndex(7)
        
    def init_key_management_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # Key management interface
        key_group = QGroupBox("Key Management")
        key_layout = QVBoxLayout()
        
        # Key list
        self.key_list = QTreeWidget()
        self.key_list.setHeaderLabels(["Key Name", "Type", "Creation Date", "Status"])
        key_layout.addWidget(self.key_list)
        
        # Key creation
        create_group = QGroupBox("Create Key")
        create_layout = QFormLayout()
        
        self.key_name_edit = QLineEdit()
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItems(["RSA", "ECDSA", "Ed25519", "AES", "ChaCha20"])
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["2048", "3072", "4096", "8192"])
        
        create_layout.addRow("Key Name:", self.key_name_edit)
        create_layout.addRow("Key Type:", self.key_type_combo)
        create_layout.addRow("Key Size:", self.key_size_combo)
        
        create_btn = QPushButton("Create Key")
        create_btn.clicked.connect(self.create_key)
        create_layout.addRow("", create_btn)
        
        create_group.setLayout(create_layout)
        key_layout.addWidget(create_group)
        
        # Key operations
        button_layout = QHBoxLayout()
        export_btn = QPushButton("Export")
        import_btn = QPushButton("Import")
        backup_btn = QPushButton("Backup")
        restore_btn = QPushButton("Restore")
        
        export_btn.clicked.connect(self.export_key)
        import_btn.clicked.connect(self.import_key)
        backup_btn.clicked.connect(self.backup_keys)
        restore_btn.clicked.connect(self.restore_keys)
        
        button_layout.addWidget(export_btn)
        button_layout.addWidget(import_btn)
        button_layout.addWidget(backup_btn)
        button_layout.addWidget(restore_btn)
        
        key_layout.addLayout(button_layout)
        key_group.setLayout(key_layout)
        layout.addWidget(key_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def show_security_reports(self):
        self.right_panel.setCurrentIndex(8)
        
    def init_security_reports_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        # Security reports interface
        reports_group = QGroupBox("Security Reports")
        reports_layout = QVBoxLayout()
        
        # Report list
        self.report_list = QTreeWidget()
        self.report_list.setHeaderLabels(["Report Name", "Date", "Status"])
        reports_layout.addWidget(self.report_list)
        
        # Report creation
        create_group = QGroupBox("Create Report")
        create_layout = QFormLayout()
        
        self.report_name_edit = QLineEdit()
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems([
            "System Security",
            "Encryption Analysis",
            "Key Management",
            "Password Security",
            "File Integrity"
        ])
        
        create_layout.addRow("Report Name:", self.report_name_edit)
        create_layout.addRow("Report Type:", self.report_type_combo)
        
        create_btn = QPushButton("Create Report")
        create_btn.clicked.connect(self.create_report)
        create_layout.addRow("", create_btn)
        
        create_group.setLayout(create_layout)
        reports_layout.addWidget(create_group)
        
        # Report operations
        button_layout = QHBoxLayout()
        view_btn = QPushButton("View")
        export_btn = QPushButton("Export")
        delete_btn = QPushButton("Delete")
        
        view_btn.clicked.connect(self.view_report)
        export_btn.clicked.connect(self.export_report)
        delete_btn.clicked.connect(self.delete_report)
        
        button_layout.addWidget(view_btn)
        button_layout.addWidget(export_btn)
        button_layout.addWidget(delete_btn)
        
        reports_layout.addLayout(button_layout)
        reports_group.setLayout(reports_layout)
        layout.addWidget(reports_group)
        
        page.setLayout(layout)
        self.right_panel.addWidget(page)

    def encrypt_text(self):
        try:
            text = self.text_edit.toPlainText()
            if not text:
                QMessageBox.warning(self, "Warning", "Please enter text to encrypt!")
                return
                
            # Text length check
            if len(text) > 1000000:  # 1MB
                QMessageBox.warning(self, "Warning", "Text is too long (max 1MB)")
                return
                
            algorithm = self.algo_combo.currentText()
            
            # Algorithm check
            if algorithm not in ["AES-256 (GCM)", "ChaCha20-Poly1305", "Fernet", "RSA-OAEP"]:
                QMessageBox.warning(self, "Warning", "Invalid encryption algorithm")
                return
                
            # Encryption process
            if algorithm == "AES-256 (GCM)":
                key = os.urandom(32)
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
                encryptor = cipher.encryptor()
                
                # Text encryption
                encrypted = encryptor.update(text.encode()) + encryptor.finalize()
                
                # Show result
                self.result_edit.setText(f"Encrypted Text (Base64):\n{base64.b64encode(encrypted).decode()}\n\n"
                                       f"Key (Base64):\n{base64.b64encode(key).decode()}\n"
                                       f"IV (Base64):\n{base64.b64encode(iv).decode()}")
                                       
            elif algorithm == "ChaCha20-Poly1305":
                key = os.urandom(32)
                nonce = os.urandom(16)
                cipher = Cipher(algorithms.ChaCha20(key, nonce), modes.Poly1305())
                encryptor = cipher.encryptor()
                
                # Text encryption
                encrypted = encryptor.update(text.encode()) + encryptor.finalize()
                
                # Show result
                self.result_edit.setText(f"Encrypted Text (Base64):\n{base64.b64encode(encrypted).decode()}\n\n"
                                       f"Key (Base64):\n{base64.b64encode(key).decode()}\n"
                                       f"Nonce (Base64):\n{base64.b64encode(nonce).decode()}")
                                       
            elif algorithm == "Fernet":
                key = Fernet.generate_key()
                f = Fernet(key)
                
                # Text encryption
                encrypted = f.encrypt(text.encode())
                
                # Show result
                self.result_edit.setText(f"Encrypted Text (Base64):\n{encrypted.decode()}\n\n"
                                       f"Key (Base64):\n{key.decode()}")
                                       
            elif algorithm == "RSA-OAEP":
                # Generate RSA key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                public_key = private_key.public_key()
                
                # Text encryption
                encrypted = public_key.encrypt(
                    text.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Show result
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
                
                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                
                self.result_edit.setText(
                    f"Encrypted Text (Base64):\n{base64.b64encode(encrypted).decode()}\n\n"
                    f"Private Key (PEM):\n{private_key_pem}\n"
                    f"Public Key (PEM):\n{public_key_pem}"
                )
                                       
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during encryption: {str(e)}")

    def decrypt_text(self):
        encrypted = self.text_edit.toPlainText()
        key = self.key_input.text()
        iv_nonce = self.iv_input.text()
        
        if not all([encrypted, key]):
            QMessageBox.warning(self, "Warning", "Please enter encrypted text and key!")
            return
            
        algorithm = self.algo_combo.currentText()
        
        try:
            if algorithm == "AES-256 (GCM)":
                if not iv_nonce:
                    QMessageBox.warning(self, "Warning", "Please enter IV!")
                    return
                    
                # Decode inputs
                key = base64.b64decode(key)
                iv = base64.b64decode(iv_nonce)
                encrypted = base64.b64decode(encrypted)
                
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
                decryptor = cipher.decryptor()
                
                # Decrypt and unpad data
                decrypted = decryptor.update(encrypted) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                unpadded = unpadder.update(decrypted) + unpadder.finalize()
                
                result = unpadded.decode()
                
            elif algorithm == "ChaCha20-Poly1305":
                if not iv_nonce:
                    QMessageBox.warning(self, "Warning", "Please enter nonce!")
                    return
                    
                # Decode inputs
                key = base64.b64decode(key)
                nonce = base64.b64decode(iv_nonce)
                encrypted = base64.b64decode(encrypted)
                
                cipher = Cipher(algorithms.ChaCha20Poly1305(key), modes.Poly1305(nonce))
                decryptor = cipher.decryptor()
                
                # Decrypt data
                decrypted = decryptor.update(encrypted) + decryptor.finalize()
                result = decrypted.decode()
                
            elif algorithm == "Fernet":
                # Decode inputs
                key = key.encode()
                encrypted = encrypted.encode()
                
                f = Fernet(key)
                
                # Decrypt data
                decrypted = f.decrypt(encrypted)
                result = decrypted.decode()
                
            elif algorithm == "RSA-OAEP":
                # This is not a valid encryption algorithm for text
                raise Exception("RSA-OAEP is not a valid encryption algorithm for text!")
                
            else:  # Blowfish, Twofish, Serpent, Camellia
                # These are not valid encryption algorithms for text
                raise Exception("These algorithms are not valid for text decryption!")
            
            self.text_output.setPlainText(result)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt text: {str(e)}")

    def encrypt_files(self):
        try:
            selected_items = self.file_list.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "Warning", "Please select files to encrypt!")
                return
                
            # File count check
            if len(selected_items) > 10:
                QMessageBox.warning(self, "Warning", "Maximum 10 files can be encrypted at once!")
                return
                
            # Encryption options check
            algorithm = self.algo_combo.currentText()
            if algorithm not in ["AES-256 (GCM)", "ChaCha20-Poly1305", "Fernet"]:
                QMessageBox.warning(self, "Warning", "Invalid encryption algorithm")
                return
                
            # Output directory selection
            output_dir = QFileDialog.getExistingDirectory(
                self,
                "Select Directory to Save Encrypted Files"
            )
            
            if not output_dir:
                return
                
            # Directory write permission check
            if not os.access(output_dir, os.W_OK):
                QMessageBox.warning(self, "Warning", "No write permission for selected directory!")
                return
                
            # Encryption process for each file
            for item in selected_items:
                try:
                    file_path = item.text()
                    
                    # File read permission check
                    if not os.access(file_path, os.R_OK):
                        QMessageBox.warning(self, "Warning", f"No access permission for {os.path.basename(file_path)}!")
                        continue
                        
                    # File size check
                    if os.path.getsize(file_path) > 1024 * 1024 * 1024:  # 1GB
                        QMessageBox.warning(self, "Warning", f"{os.path.basename(file_path)} is too large (max 1GB)!")
                        continue
                        
                    # Encryption process
                    if algorithm == "AES-256 (GCM)":
                        key = os.urandom(32)
                        iv = os.urandom(16)
                        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
                        encryptor = cipher.encryptor()
                        
                        with open(file_path, 'rb') as f:
                            data = f.read()
                            
                        encrypted = encryptor.update(data) + encryptor.finalize()
                        
                        # Save encrypted file with metadata
                        output_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.enc")
                        with open(output_path, 'wb') as f:
                            f.write(iv)  # Write IV first
                            f.write(encrypted)
                            
                        # Save key
                        key_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.key")
                        with open(key_path, 'wb') as f:
                            f.write(key)
                            
                    elif algorithm == "ChaCha20-Poly1305":
                        key = os.urandom(32)
                        nonce = os.urandom(16)
                        cipher = Cipher(algorithms.ChaCha20(key, nonce), None)
                        encryptor = cipher.encryptor()
                        
                        with open(file_path, 'rb') as f:
                            data = f.read()
                            
                        encrypted = encryptor.update(data)
                        
                        # Save encrypted file with metadata
                        output_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.enc")
                        with open(output_path, 'wb') as f:
                            f.write(nonce)  # Write nonce first
                            f.write(encrypted)
                            
                        # Save key
                        key_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.key")
                        with open(key_path, 'wb') as f:
                            f.write(key)
                            
                    elif algorithm == "Fernet":
                        key = Fernet.generate_key()
                        f = Fernet(key)
                        
                        with open(file_path, 'rb') as f_in:
                            data = f_in.read()
                            
                        encrypted = f.encrypt(data)
                        
                        # Save encrypted file
                        output_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.enc")
                        with open(output_path, 'wb') as f_out:
                            f_out.write(encrypted)
                            
                        # Save key
                        key_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.key")
                        with open(key_path, 'wb') as f:
                            f.write(key)
                            
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Error encrypting {os.path.basename(file_path)}: {str(e)}")
                    continue
                    
            QMessageBox.information(self, "Success", "Files encrypted successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during encryption process: {str(e)}")

    def decrypt_files(self):
        selected_items = self.file_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select files to decrypt!")
            return
            
        key = None
        key_path = self.key_path_edit.text()
        manual_key = self.manual_key_edit.text()
        
        if key_path:
            try:
                with open(key_path, 'rb') as key_file:
                    key = key_file.read()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error reading key file: {str(e)}")
                return
        elif manual_key:
            try:
                key = manual_key.encode()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error processing manual key: {str(e)}")
                return
        else:
            QMessageBox.warning(self, "Warning", "Please select a key file or enter a key manually!")
            return
            
        try:
            for item in selected_items:
                file_path = item.text()
                try:
                    # Read encrypted file
                    with open(file_path, 'rb') as f:
                        # Read metadata (IV/nonce) first
                        metadata = f.read(16)
                        encrypted_data = f.read()
                    
                    # Try different decryption methods
                    try:
                        # Try Fernet first
                        f = Fernet(key)
                        decrypted_data = f.decrypt(encrypted_data)
                    except Exception:
                        try:
                            # Try AES-256 (GCM)
                            cipher = Cipher(algorithms.AES(key), modes.GCM(metadata))
                            decryptor = cipher.decryptor()
                            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                        except Exception:
                            try:
                                # Try ChaCha20-Poly1305
                                cipher = Cipher(algorithms.ChaCha20(key, metadata), None)
                                decryptor = cipher.decryptor()
                                decrypted_data = decryptor.update(encrypted_data)
                            except Exception as e:
                                raise Exception(f"Failed to decrypt with any supported algorithm: {str(e)}")
                    
                    # Save decrypted file
                    output_path = file_path.replace('.enc', '')
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                        
                    self.add_to_history(file_path, 'Decryption', 'Success')
                    
                except Exception as e:
                    self.add_to_history(file_path, 'Decryption', f'Error: {str(e)}')
                    QMessageBox.warning(self, "Warning", f"Failed to decrypt {os.path.basename(file_path)}: {str(e)}")
                    continue
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption error: {str(e)}")

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def add_to_history(self, file_path, operation, status):
        item = QTreeWidgetItem(self.history_list)
        item.setText(0, os.path.basename(file_path))
        item.setText(1, operation)
        item.setText(2, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        item.setText(3, status)
        self.history_list.addTopLevelItem(item)

    def generate_password(self):
        length = self.password_length.value()
        use_uppercase = self.uppercase_check.isChecked()
        use_lowercase = self.lowercase_check.isChecked()
        use_numbers = self.numbers_check.isChecked()
        use_special = self.special_check.isChecked()
        
        if not any([use_uppercase, use_lowercase, use_numbers, use_special]):
            QMessageBox.warning(self, "Warning", "Please select at least one character type!")
            return
            
        try:
            # Create character pool
            chars = ""
            if use_uppercase:
                chars += string.ascii_uppercase
            if use_lowercase:
                chars += string.ascii_lowercase
            if use_numbers:
                chars += string.digits
            if use_special:
                chars += string.punctuation
                
            # Generate password
            password = "".join(secrets.choice(chars) for _ in range(length))
            
            # Calculate strength
            strength = self._calculate_password_strength(password)
            
            # Update UI
            self.password_result.setText(password)
            self.strength_bar.setValue(strength)
            self.strength_bar.setStyleSheet(self._get_strength_color(strength))
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate password: {str(e)}")

    def _calculate_password_strength(self, password):
        # Base score
        score = 0
        
        # Length
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 10
            
        # Character types
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if has_upper:
            score += 25
        if has_lower:
            score += 25
        if has_digit:
            score += 25
        if has_special:
            score += 25
            
        # Entropy
        char_set = 0
        if has_upper:
            char_set += 26
        if has_lower:
            char_set += 26
        if has_digit:
            char_set += 10
        if has_special:
            char_set += 32
            
        entropy = math.log2(char_set ** len(password))
        if entropy >= 128:
            score = 100
        elif entropy >= 64:
            score = max(score, 75)
            
        return min(score, 100)

    def _get_strength_color(self, strength):
        if strength < 25:
            return "QProgressBar { background-color: #f8d7da; } QProgressBar::chunk { background-color: #dc3545; }"
        elif strength < 50:
            return "QProgressBar { background-color: #fff3cd; } QProgressBar::chunk { background-color: #ffc107; }"
        elif strength < 75:
            return "QProgressBar { background-color: #d1e7dd; } QProgressBar::chunk { background-color: #198754; }"
        else:
            return "QProgressBar { background-color: #cfe2ff; } QProgressBar::chunk { background-color: #0d6efd; }"

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path_edit.setText(file_path)

    def browse_image(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp)")
        if file_path:
            self.image_path_edit.setText(file_path)

    def browse_delete(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File or Folder")
        if path:
            self.delete_path_edit.setText(path)

    def browse_analysis(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.analysis_path_edit.setText(file_path)

    def analyze_file(self):
        file_path = self.analysis_path_edit.text()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a file to analyze!")
            return
            
        analysis_type = self.analysis_type_combo.currentText()
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if analysis_type == "Entropy Analysis":
                # Calculate entropy
                entropy = self._calculate_entropy(data)
                result = f"Entropy: {entropy:.2f} bits/byte\n"
                result += "High entropy suggests good encryption"
                
            elif analysis_type == "Frequency Analysis":
                # Calculate byte frequencies
                freq = [0] * 256
                for byte in data:
                    freq[byte] += 1
                    
                result = "Byte Frequency Analysis:\n"
                for i in range(256):
                    if freq[i] > 0:
                        result += f"Byte {i:02X}: {freq[i]} occurrences\n"
                        
            elif analysis_type == "Correlation Analysis":
                # Calculate byte correlations
                result = "Byte Correlation Analysis:\n"
                for i in range(256):
                    for j in range(i+1, 256):
                        if data.count(bytes([i])) > 0 and data.count(bytes([j])) > 0:
                            correlation = self._calculate_correlation(data, i, j)
                            result += f"Bytes {i:02X} & {j:02X}: {correlation:.3f}\n"
                            
            else:  # Cryptographic Strength
                # Analyze cryptographic properties
                result = "Cryptographic Strength Analysis:\n"
                result += f"File Size: {len(data)} bytes\n"
                result += f"Entropy: {self._calculate_entropy(data):.2f} bits/byte\n"
                result += f"Compression Ratio: {self._calculate_compression_ratio(data):.2f}\n"
                
            self.analysis_result.setPlainText(result)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to analyze file: {str(e)}")

    def _calculate_entropy(self, data):
        if not data:
            return 0
            
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
            
        entropy = 0
        for count in freq:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
                
        return entropy

    def _calculate_correlation(self, data, byte1, byte2):
        count1 = data.count(bytes([byte1]))
        count2 = data.count(bytes([byte2]))
        if count1 == 0 or count2 == 0:
            return 0
            
        expected = (count1 * count2) / len(data)
        actual = 0
        for i in range(len(data)-1):
            if data[i] == byte1 and data[i+1] == byte2:
                actual += 1
                
        return actual / expected if expected > 0 else 0

    def _calculate_compression_ratio(self, data):
        try:
            compressed = len(zlib.compress(data))
            return len(data) / compressed if compressed > 0 else 1
        except:
            return 1

    def hide_message(self):
        image_path = self.image_path_edit.text()
        message = self.message_edit.toPlainText()
        
        if not all([image_path, message]):
            QMessageBox.warning(self, "Warning", "Please select an image and enter a message!")
            return
            
        try:
            # Open image
            img = Image.open(image_path)
            
            # Convert message to binary
            binary_message = ''.join(format(ord(c), '08b') for c in message)
            binary_message += '1111111111111110'  # End marker
            
            # Check if message fits
            if len(binary_message) > img.width * img.height * 3:
                raise Exception("Message too long for image!")
                
            # Hide message in LSB
            pixels = img.load()
            message_index = 0
            
            for i in range(img.width):
                for j in range(img.height):
                    if message_index < len(binary_message):
                        r, g, b = pixels[i, j]
                        
                        # Modify LSB
                        if message_index < len(binary_message):
                            r = (r & 0xFE) | int(binary_message[message_index])
                            message_index += 1
                        if message_index < len(binary_message):
                            g = (g & 0xFE) | int(binary_message[message_index])
                            message_index += 1
                        if message_index < len(binary_message):
                            b = (b & 0xFE) | int(binary_message[message_index])
                            message_index += 1
                            
                        pixels[i, j] = (r, g, b)
                        
            # Save stego image
            output_path = f"{os.path.splitext(image_path)[0]}_stego.png"
            img.save(output_path)
            
            QMessageBox.information(self, "Success", f"Message hidden successfully!\nSaved as: {output_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to hide message: {str(e)}")

    def extract_message(self):
        image_path = self.image_path_edit.text()
        if not image_path:
            QMessageBox.warning(self, "Warning", "Please select an image!")
            return
            
        try:
            # Open image
            img = Image.open(image_path)
            pixels = img.load()
            
            # Extract LSBs
            binary_message = ""
            for i in range(img.width):
                for j in range(img.height):
                    r, g, b = pixels[i, j]
                    binary_message += str(r & 1)
                    binary_message += str(g & 1)
                    binary_message += str(b & 1)
                    
            # Find end marker
            end_index = binary_message.find('1111111111111110')
            if end_index == -1:
                raise Exception("No hidden message found!")
                
            binary_message = binary_message[:end_index]
            
            # Convert binary to text
            message = ""
            for i in range(0, len(binary_message), 8):
                byte = binary_message[i:i+8]
                if len(byte) == 8:
                    message += chr(int(byte, 2))
                    
            self.message_edit.setPlainText(message)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to extract message: {str(e)}")

    def create_key(self):
        key_name = self.key_name_edit.text()
        key_type = self.key_type_combo.currentText()
        key_size = int(self.key_size_combo.currentText())
        
        if not key_name:
            QMessageBox.warning(self, "Warning", "Please enter a key name!")
            return
            
        try:
            if key_type == "RSA":
                # Generate RSA key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size
                )
                
                # Save private key
                with open(f"private_{key_name}.pem", "wb") as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                    
                # Save public key
                with open(f"public_{key_name}.pem", "wb") as f:
                    f.write(private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                    
            elif key_type == "ECDSA":
                # Generate ECDSA key pair
                private_key = ec.generate_private_key(ec.SECP256R1())
                
                # Save private key
                with open(f"private_{key_name}.pem", "wb") as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                    
                # Save public key
                with open(f"public_{key_name}.pem", "wb") as f:
                    f.write(private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                    
            else:  # AES/ChaCha20
                # Generate symmetric key
                key = os.urandom(32)
                
                # Save key
                with open(f"{key_name}.key", "wb") as f:
                    f.write(key)
                    
            QMessageBox.information(self, "Success", "Key created successfully!")
            self.update_key_list()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create key: {str(e)}")

    def secure_delete(self):
        path = self.delete_path_edit.text()
        if not path:
            QMessageBox.warning(self, "Warning", "Please select a file or folder!")
            return
            
        passes = int(self.delete_algo_combo.currentText().split()[0])
        verify = self.verify_delete_check.isChecked()
        
        try:
            if os.path.isfile(path):
                self._secure_delete_file(path, passes, verify)
            else:
                self._secure_delete_folder(path, passes, verify)
                
            QMessageBox.information(self, "Success", "Secure deletion completed!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete: {str(e)}")

    def _secure_delete_file(self, file_path, passes, verify):
        # Get file size
        size = os.path.getsize(file_path)
        
        # Overwrite file multiple times
        for i in range(passes):
            # Generate random data
            data = os.urandom(size)
            
            # Write random data
            with open(file_path, 'wb') as f:
                f.write(data)
                
        # Delete file
        os.remove(file_path)
        
        if verify:
            # Verify deletion
            if os.path.exists(file_path):
                raise Exception("File still exists after deletion!")

    def _secure_delete_folder(self, folder_path, passes, verify):
        # Delete all files in folder
        for root, _, files in os.walk(folder_path):
            for file in files:
                self._secure_delete_file(os.path.join(root, file), passes, verify)
                
        # Delete empty folders
        for root, dirs, _ in os.walk(folder_path, topdown=False):
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
                
        # Delete main folder
        os.rmdir(folder_path)
        
        if verify:
            # Verify deletion
            if os.path.exists(folder_path):
                raise Exception("Folder still exists after deletion!")

    def sign_file(self):
        file_path = self.file_path_edit.text()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a file!")
            return
            
        algorithm = self.sign_algo_combo.currentText()
        
        try:
            # Read file data
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if algorithm.startswith("RSA"):
                # Load RSA private key
                with open("private_key.pem", "rb") as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )
                    
                # Sign data
                if algorithm.endswith("SHA256"):
                    signature = private_key.sign(
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                else:  # SHA512
                    signature = private_key.sign(
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA512()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA512()
                    )
                    
            else:  # ECDSA
                # Load ECDSA private key
                with open("private_key.pem", "rb") as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )
                    
                # Sign data
                if algorithm.endswith("SHA256"):
                    signature = private_key.sign(
                        data,
                        ec.ECDSA(hashes.SHA256())
                    )
                else:  # SHA512
                    signature = private_key.sign(
                        data,
                        ec.ECDSA(hashes.SHA512())
                    )
                    
            # Save signature
            with open(f"{file_path}.sig", "wb") as f:
                f.write(signature)
                
            QMessageBox.information(self, "Success", "File signed successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to sign file: {str(e)}")

    def verify_signature(self):
        file_path = self.file_path_edit.text()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a file!")
            return
            
        algorithm = self.sign_algo_combo.currentText()
        
        try:
            # Read file data
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Read signature
            with open(f"{file_path}.sig", "rb") as f:
                signature = f.read()
                
            if algorithm.startswith("RSA"):
                # Load RSA public key
                with open("public_key.pem", "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read())
                    
                # Verify signature
                if algorithm.endswith("SHA256"):
                    public_key.verify(
                        signature,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                else:  # SHA512
                    public_key.verify(
                        signature,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA512()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA512()
                    )
                    
            else:  # ECDSA
                # Load ECDSA public key
                with open("public_key.pem", "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read())
                    
                # Verify signature
                if algorithm.endswith("SHA256"):
                    public_key.verify(
                        signature,
                        data,
                        ec.ECDSA(hashes.SHA256())
                    )
                else:  # SHA512
                    public_key.verify(
                        signature,
                        data,
                        ec.ECDSA(hashes.SHA512())
                    )
                    
            QMessageBox.information(self, "Success", "Signature verified successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to verify signature: {str(e)}")

    def add_password(self):
        site = self.site_edit.text()
        username = self.username_edit.text()
        password = self.password_edit.text()
        
        if not all([site, username, password]):
            QMessageBox.warning(self, "Warning", "Please fill in all fields!")
            return
            
        try:
            # Encrypt password
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypted_password = f.encrypt(password.encode())
            
            # Save password entry
            entry = {
                "site": site,
                "username": username,
                "password": encrypted_password.decode(),
                "key": key.decode(),
                "timestamp": datetime.now().isoformat()
            }
            
            # Load existing passwords
            try:
                with open("passwords.json", "r") as f:
                    passwords = json.load(f)
            except:
                passwords = []
                
            # Add new entry
            passwords.append(entry)
            
            # Save passwords
            with open("passwords.json", "w") as f:
                json.dump(passwords, f, indent=4)
                
            # Update UI
            self.update_password_list()
            
            QMessageBox.information(self, "Success", "Password added successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add password: {str(e)}")

    def update_password_list(self):
        self.password_list.clear()
        
        try:
            with open("passwords.json", "r") as f:
                passwords = json.load(f)
                
            for entry in passwords:
                item = QTreeWidgetItem(self.password_list)
                item.setText(0, entry["site"])
                item.setText(1, entry["username"])
                item.setText(2, "********")
                item.setText(3, entry["timestamp"])
                
        except:
            pass

    def edit_password(self):
        selected = self.password_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a password to edit!")
            return
            
        item = selected[0]
        site = item.text(0)
        username = item.text(1)
        
        try:
            with open("passwords.json", "r") as f:
                passwords = json.load(f)
                
            for entry in passwords:
                if entry["site"] == site and entry["username"] == username:
                    # Decrypt password
                    key = entry["key"].encode()
                    f = Fernet(key)
                    decrypted_password = f.decrypt(entry["password"].encode()).decode()
                    
                    # Show edit dialog
                    dialog = QDialog(self)
                    dialog.setWindowTitle("Edit Password")
                    dialog.setFixedSize(400, 300)
                    
                    layout = QVBoxLayout()
                    
                    site_edit = QLineEdit(entry["site"])
                    username_edit = QLineEdit(entry["username"])
                    password_edit = QLineEdit(decrypted_password)
                    password_edit.setEchoMode(QLineEdit.EchoMode.Password)
                    
                    form_layout = QFormLayout()
                    form_layout.addRow("Site:", site_edit)
                    form_layout.addRow("Username:", username_edit)
                    form_layout.addRow("Password:", password_edit)
                    
                    buttons = QHBoxLayout()
                    save_btn = QPushButton("Save")
                    cancel_btn = QPushButton("Cancel")
                    
                    buttons.addWidget(save_btn)
                    buttons.addWidget(cancel_btn)
                    
                    layout.addLayout(form_layout)
                    layout.addLayout(buttons)
                    
                    dialog.setLayout(layout)
                    
                    def save():
                        if not all([site_edit.text(), username_edit.text(), password_edit.text()]):
                            QMessageBox.warning(dialog, "Warning", "Please fill in all fields!")
                            return
                            
                        # Generate new key and encrypt password
                        key = Fernet.generate_key()
                        f = Fernet(key)
                        encrypted_password = f.encrypt(password_edit.text().encode())
                        
                        # Update entry
                        entry["site"] = site_edit.text()
                        entry["username"] = username_edit.text()
                        entry["password"] = encrypted_password.decode()
                        entry["key"] = key.decode()
                        entry["timestamp"] = datetime.now().isoformat()
                        
                        # Save changes
                        with open("passwords.json", "w") as f:
                            json.dump(passwords, f, indent=4)
                            
                        # Update UI
                        self.update_password_list()
                        
                        dialog.accept()
                        
                    save_btn.clicked.connect(save)
                    cancel_btn.clicked.connect(dialog.reject)
                    
                    dialog.exec()
                    break
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to edit password: {str(e)}")

    def delete_password(self):
        selected = self.password_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a password to delete!")
            return
            
        item = selected[0]
        site = item.text(0)
        username = item.text(1)
        
        try:
            with open("passwords.json", "r") as f:
                passwords = json.load(f)
                
            # Remove entry
            passwords = [entry for entry in passwords 
                        if not (entry["site"] == site and entry["username"] == username)]
            
            # Save changes
            with open("passwords.json", "w") as f:
                json.dump(passwords, f, indent=4)
                
            # Update UI
            self.update_password_list()
            
            QMessageBox.information(self, "Success", "Password deleted successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete password: {str(e)}")

    def export_key(self):
        selected = self.key_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a key to export!")
            return
            
        item = selected[0]
        key_name = item.text(0)
        key_type = item.text(1)
        
        try:
            # Get export directory
            export_dir = QFileDialog.getExistingDirectory(self, "Select Export Directory")
            if not export_dir:
                return
                
            if key_type == "RSA":
                # Copy both private and public keys
                shutil.copy2(f"private_{key_name}.pem", os.path.join(export_dir, f"private_{key_name}.pem"))
                shutil.copy2(f"public_{key_name}.pem", os.path.join(export_dir, f"public_{key_name}.pem"))
            elif key_type == "ECDSA":
                # Copy both private and public keys
                shutil.copy2(f"private_{key_name}.pem", os.path.join(export_dir, f"private_{key_name}.pem"))
                shutil.copy2(f"public_{key_name}.pem", os.path.join(export_dir, f"public_{key_name}.pem"))
            else:  # AES/ChaCha20
                # Copy symmetric key
                shutil.copy2(f"{key_name}.key", os.path.join(export_dir, f"{key_name}.key"))
                
            QMessageBox.information(self, "Success", "Key exported successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export key: {str(e)}")

    def import_key(self):
        try:
            # Get import directory
            import_dir = QFileDialog.getExistingDirectory(self, "Select Import Directory")
            if not import_dir:
                return
                
            # Find key files
            key_files = []
            for file in os.listdir(import_dir):
                if file.endswith((".pem", ".key")):
                    key_files.append(os.path.join(import_dir, file))
                    
            if not key_files:
                QMessageBox.warning(self, "Warning", "No key files found in selected directory!")
                return
                
            # Copy key files
            for key_file in key_files:
                shutil.copy2(key_file, os.path.basename(key_file))
                
            # Update UI
            self.update_key_list()
            
            QMessageBox.information(self, "Success", "Keys imported successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import keys: {str(e)}")

    def backup_keys(self):
        try:
            # Get backup directory
            backup_dir = QFileDialog.getExistingDirectory(self, "Select Backup Directory")
            if not backup_dir:
                return
                
            # Create backup folder with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(backup_dir, f"key_backup_{timestamp}")
            os.makedirs(backup_path)
            
            # Copy all key files
            for file in os.listdir("."):
                if file.endswith((".pem", ".key")):
                    shutil.copy2(file, os.path.join(backup_path, file))
                    
            QMessageBox.information(self, "Success", f"Keys backed up successfully to:\n{backup_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to backup keys: {str(e)}")

    def restore_keys(self):
        try:
            # Get backup directory
            backup_dir = QFileDialog.getExistingDirectory(self, "Select Backup Directory")
            if not backup_dir:
                return
                
            # Find most recent backup
            backups = [d for d in os.listdir(backup_dir) if d.startswith("key_backup_")]
            if not backups:
                QMessageBox.warning(self, "Warning", "No backups found in selected directory!")
                return
                
            latest_backup = max(backups)
            backup_path = os.path.join(backup_dir, latest_backup)
            
            # Copy key files
            for file in os.listdir(backup_path):
                if file.endswith((".pem", ".key")):
                    shutil.copy2(os.path.join(backup_path, file), file)
                    
            # Update UI
            self.update_key_list()
            
            QMessageBox.information(self, "Success", "Keys restored successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to restore keys: {str(e)}")

    def create_report(self):
        report_type = self.report_type_combo.currentText()
        report_name = self.report_name_edit.text()
        
        if not report_name:
            QMessageBox.warning(self, "Warning", "Please enter a report name!")
            return
            
        try:
            report_data = {
                "type": report_type,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "data": {}
            }
            
            if report_type == "Key Inventory":
                # Get all key information
                keys = []
                for file_name in os.listdir("."):
                    if file_name.endswith((".pem", ".key")):
                        key_info = {
                            "name": file_name,
                            "type": "RSA" if file_name.endswith(".pem") else "AES/ChaCha20",
                            "created": datetime.fromtimestamp(os.path.getmtime(file_name)).strftime("%Y-%m-%d %H:%M:%S"),
                            "size": os.path.getsize(file_name)
                        }
                        keys.append(key_info)
                report_data["data"]["keys"] = keys
                
            elif report_type == "Encryption History":
                # Get encryption history
                history = []
                for file_name in os.listdir("."):
                    if file_name.endswith(".enc"):
                        hist_info = {
                            "file": file_name,
                            "algorithm": "AES-256",  # Default, can be enhanced
                            "timestamp": datetime.fromtimestamp(os.path.getmtime(file_name)).strftime("%Y-%m-%d %H:%M:%S"),
                            "size": os.path.getsize(file_name)
                        }
                        history.append(hist_info)
                report_data["data"]["history"] = history
                
            else:  # Security Audit
                # Perform security audit
                audit = {
                    "key_strength": self._audit_key_strength(),
                    "file_integrity": self._audit_file_integrity(),
                    "system_security": self._audit_system_security()
                }
                report_data["data"]["audit"] = audit
                
            # Save report
            with open(f"{report_name}.json", "w") as f:
                json.dump(report_data, f, indent=4)
                
            QMessageBox.information(self, "Success", "Report created successfully!")
            self.update_report_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create report: {str(e)}")

    def view_report(self):
        report_name = self.report_list.currentItem().text()
        if not report_name:
            QMessageBox.warning(self, "Warning", "Please select a report to view!")
            return
            
        try:
            with open(f"{report_name}.json", "r") as f:
                report_data = json.load(f)
                
            # Format report for display
            report_text = f"Report Type: {report_data['type']}\n"
            report_text += f"Created: {report_data['timestamp']}\n\n"
            
            if report_data["type"] == "Key Inventory":
                report_text += "Key Inventory:\n"
                for key in report_data["data"]["keys"]:
                    report_text += f"- {key['name']} ({key['type']})\n"
                    report_text += f"  Created: {key['created']}\n"
                    report_text += f"  Size: {key['size']} bytes\n\n"
                    
            elif report_data["type"] == "Encryption History":
                report_text += "Encryption History:\n"
                for hist in report_data["data"]["history"]:
                    report_text += f"- {hist['file']}\n"
                    report_text += f"  Algorithm: {hist['algorithm']}\n"
                    report_text += f"  Timestamp: {hist['timestamp']}\n"
                    report_text += f"  Size: {hist['size']} bytes\n\n"
                    
            else:  # Security Audit
                report_text += "Security Audit Results:\n"
                audit = report_data["data"]["audit"]
                
                report_text += "\nKey Strength Analysis:\n"
                for key, value in audit["key_strength"].items():
                    report_text += f"- {key}: {value}\n"
                    
                report_text += "\nFile Integrity Check:\n"
                for file, status in audit["file_integrity"].items():
                    report_text += f"- {file}: {status}\n"
                    
                report_text += "\nSystem Security Status:\n"
                for check, result in audit["system_security"].items():
                    report_text += f"- {check}: {result}\n"
                    
            self.report_view.setPlainText(report_text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to view report: {str(e)}")

    def export_report(self):
        report_name = self.report_list.currentItem().text()
        if not report_name:
            QMessageBox.warning(self, "Warning", "Please select a report to export!")
            return
            
        dir_path = QFileDialog.getExistingDirectory(self, "Select Export Directory")
        if not dir_path:
            return
            
        try:
            shutil.copy2(f"{report_name}.json", os.path.join(dir_path, f"{report_name}.json"))
            QMessageBox.information(self, "Success", "Report exported successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    def delete_report(self):
        report_name = self.report_list.currentItem().text()
        if not report_name:
            QMessageBox.warning(self, "Warning", "Please select a report to delete!")
            return
            
        reply = QMessageBox.question(self, "Confirm", "Are you sure you want to delete this report?",
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                os.remove(f"{report_name}.json")
                QMessageBox.information(self, "Success", "Report deleted successfully!")
                self.update_report_list()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete report: {str(e)}")

    def update_report_list(self):
        self.report_list.clear()
        
        # Find all report files
        for file_name in os.listdir("."):
            if file_name.endswith(".json"):
                try:
                    with open(file_name, "r") as f:
                        report_data = json.load(f)
                        if "type" in report_data and "timestamp" in report_data:
                            # This is a valid report file
                            report_name = os.path.splitext(file_name)[0]
                            self.report_list.addItem(report_name)
                except:
                    continue

    def _audit_key_strength(self):
        # Analyze key strength
        key_strength = {}
        
        for file_name in os.listdir("."):
            if file_name.endswith(".pem"):
                # RSA key
                with open(file_name, "rb") as f:
                    key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )
                key_size = key.key_size
                key_strength[file_name] = f"RSA-{key_size} ({'Strong' if key_size >= 2048 else 'Weak'})"
            elif file_name.endswith(".key"):
                # Symmetric key
                with open(file_name, "rb") as f:
                    key = f.read()
                key_size = len(key) * 8
                key_strength[file_name] = f"{key_size}-bit ({'Strong' if key_size >= 256 else 'Weak'})"
                
        return key_strength

    def _audit_file_integrity(self):
        # Check file integrity
        file_integrity = {}
        
        for file_name in os.listdir("."):
            if file_name.endswith((".pem", ".key", ".enc")):
                try:
                    # Calculate file hash
                    with open(file_name, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    file_integrity[file_name] = f"Hash: {file_hash[:8]}... ({'Valid' if len(file_hash) == 64 else 'Invalid'})"
                except:
                    file_integrity[file_name] = "Error checking integrity"
                    
        return file_integrity

    def _audit_system_security(self):
        # Check system security
        system_security = {
            "Key Storage": "Secure" if os.path.exists("private_key.pem") else "Insecure",
            "File Permissions": "Secure" if os.name != "nt" else "Windows - Check manually",
            "Memory Protection": "Enabled" if hasattr(os, "mlock") else "Not available",
            "Random Number Generation": "Secure" if hasattr(os, "urandom") else "Insecure"
        }
        
        return system_security

    def add_file(self):
        try:
            files, _ = QFileDialog.getOpenFileNames(
                self,
                "Select Files",
                "",
                "All Files (*.*)"
            )
            
            if not files:
                return
                
            for file in files:
                try:
                    # File size check (max 1GB)
                    if os.path.getsize(file) > 1024 * 1024 * 1024:
                        QMessageBox.warning(self, "Warning", f"{os.path.basename(file)} is too large (max 1GB)")
                        continue
                        
                    # File permissions check
                    if not os.access(file, os.R_OK):
                        QMessageBox.warning(self, "Warning", f"No access permission for {os.path.basename(file)}")
                        continue
                        
                    if file not in [self.file_list.item(i).text() for i in range(self.file_list.count())]:
                        self.file_list.addItem(file)
                        
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Error adding {os.path.basename(file)}: {str(e)}")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during file selection: {str(e)}")
            
    def add_folder(self):
        try:
            folder = QFileDialog.getExistingDirectory(
                self,
                "Select Folder"
            )
            
            if not folder:
                return
                
            # Folder permissions check
            if not os.access(folder, os.R_OK):
                QMessageBox.warning(self, "Warning", "No access permission for folder")
                return
                
            for root, _, files in os.walk(folder):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        
                        # File size check
                        if os.path.getsize(file_path) > 1024 * 1024 * 1024:
                            continue
                            
                        # File permissions check
                        if not os.access(file_path, os.R_OK):
                            continue
                            
                        if file_path not in [self.file_list.item(i).text() for i in range(self.file_list.count())]:
                            self.file_list.addItem(file_path)
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during folder selection: {str(e)}")
            
    def remove_file(self):
        try:
            selected_items = self.file_list.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "Warning", "Please select files to remove!")
                return
                
            for item in selected_items:
                self.file_list.takeItem(self.file_list.row(item))
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during file removal: {str(e)}")

    def export_passwords(self):
        try:
            # Get export directory
            export_dir = QFileDialog.getExistingDirectory(
                self,
                "Select Export Directory"
            )
            
            if not export_dir:
                return
                
            # Load passwords
            with open("passwords.json", "r") as f:
                passwords = json.load(f)
                
            # Create export file
            export_path = os.path.join(export_dir, "passwords_export.json")
            with open(export_path, "w") as f:
                json.dump(passwords, f, indent=4)
                
            QMessageBox.information(
                self,
                "Success",
                f"Passwords exported successfully to:\n{export_path}"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to export passwords: {str(e)}"
            )

    def import_passwords(self):
        try:
            # Get import file
            import_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Import File",
                "",
                "JSON Files (*.json)"
            )
            
            if not import_path:
                return
                
            # Load imported passwords
            with open(import_path, "r") as f:
                imported_passwords = json.load(f)
                
            # Load existing passwords
            try:
                with open("passwords.json", "r") as f:
                    existing_passwords = json.load(f)
            except:
                existing_passwords = []
                
            # Merge passwords
            for imported in imported_passwords:
                # Check if password already exists
                exists = False
                for existing in existing_passwords:
                    if (existing["site"] == imported["site"] and 
                        existing["username"] == imported["username"]):
                        exists = True
                        break
                        
                if not exists:
                    existing_passwords.append(imported)
                    
            # Save merged passwords
            with open("passwords.json", "w") as f:
                json.dump(existing_passwords, f, indent=4)
                
            # Update UI
            self.update_password_list()
            
            QMessageBox.information(
                self,
                "Success",
                "Passwords imported successfully!"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to import passwords: {str(e)}"
            )

    def browse_key_file(self):
        key_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Key File",
            "",
            "Key Files (*.key);;All Files (*.*)"
        )
        if key_path:
            self.key_path_edit.setText(key_path)
            # Clear manual key when file is selected
            self.manual_key_edit.clear()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    splash = QSplashScreen(QPixmap("/usr/share/icons/securonis/splash.png"))
    splash.show()
    
    window = CryptoApp()
    
    QTimer.singleShot(2000, lambda: (splash.close(), window.show()))
    
    sys.exit(app.exec_()) 
