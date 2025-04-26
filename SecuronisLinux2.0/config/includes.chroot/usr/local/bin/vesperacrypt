#!/usr/bin/env python3

import sys
import os
import hashlib
import base64
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                           QVBoxLayout, QHBoxLayout, QWidget, QFileDialog, 
                           QLineEdit, QMessageBox)
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet

class VesperaCrypt(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VesperaCrypt")
        self.setFixedSize(600, 400)
        self.setWindowIcon(QIcon("/usr/share/icons/securonis/vespera.png"))
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Logo
        logo_label = QLabel()
        pixmap = QPixmap("/usr/share/icons/securonis/vespera.png")
        scaled_pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(scaled_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Title
        title_label = QLabel("VesperaCrypt - File Encryption")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # File selection button
        self.file_path = ""
        self.file_button = QPushButton("Select File")
        self.file_button.clicked.connect(self.select_file)
        layout.addWidget(self.file_button)
        
        # Selected file path
        self.file_label = QLabel("No file selected")
        self.file_label.setAlignment(Qt.AlignCenter)
        self.file_label.setStyleSheet("color: #cccccc;")
        layout.addWidget(self.file_label)
        
        # Password input
        password_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        # Encryption/Decryption buttons
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.decrypt_button = QPushButton("Decrypt")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        layout.addLayout(button_layout)
        
        # Status message
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #cccccc;")
        layout.addWidget(self.status_label)
        
        # Dark theme style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QPushButton {
                background-color: #4a90e2;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #357abd;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #444444;
                border-radius: 4px;
                background-color: #2d2d2d;
                color: #ffffff;
            }
            QLineEdit:focus {
                border: 1px solid #4a90e2;
            }
        """)

    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if file_name:
            self.file_path = file_name
            self.file_label.setText(os.path.basename(file_name))
            
            # Enable/disable buttons based on file extension
            if file_name.endswith('.vcrypt'):
                self.encrypt_button.setEnabled(False)
                self.decrypt_button.setEnabled(True)
            else:
                self.encrypt_button.setEnabled(True)
                self.decrypt_button.setEnabled(False)

    def get_key_from_password(self, password):
        # Convert password to key securely
        salt = b"VesperaCryptSalt"  # Fixed salt value
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000,  # High iteration count
            dklen=32
        )
        return base64.urlsafe_b64encode(key)

    def is_encrypted_file(self, file_path):
        """Check if the file is encrypted"""
        try:
            with open(file_path, 'rb') as file:
                # Read first 10 bytes
                header = file.read(10)
                # Check for Fernet encryption format
                return header.startswith(b'gAAAAA')
        except:
            return False

    def encrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please select a file!")
            return
            
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password!")
            return
            
        try:
            key = self.get_key_from_password(password)
            f = Fernet(key)
            
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                
            encrypted_data = f.encrypt(file_data)
            
            # Keep original file extension and add .vcrypt
            base_name, ext = os.path.splitext(self.file_path)
            output_path = base_name + ext + '.vcrypt'
            
            with open(output_path, 'wb') as file:
                file.write(encrypted_data)
                
            self.status_label.setText("File encrypted successfully!")
            self.status_label.setStyleSheet("color: #4CAF50;")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred during encryption: {str(e)}")

    def decrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please select a file!")
            return
            
        if not self.file_path.endswith('.vcrypt'):
            QMessageBox.warning(self, "Error", "Please select an encrypted file (.vcrypt extension)!")
            return
            
        if not self.is_encrypted_file(self.file_path):
            QMessageBox.warning(self, "Error", "Selected file is not encrypted with VesperaCrypt!")
            return
            
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password!")
            return
            
        try:
            key = self.get_key_from_password(password)
            f = Fernet(key)
            
            with open(self.file_path, 'rb') as file:
                encrypted_data = file.read()
                
            decrypted_data = f.decrypt(encrypted_data)
            
            # Remove .vcrypt extension
            output_path = self.file_path.replace('.vcrypt', '')
            
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
                
            self.status_label.setText("File decrypted successfully!")
            self.status_label.setStyleSheet("color: #4CAF50;")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred during decryption: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = VesperaCrypt()
    window.show()
    sys.exit(app.exec_()) 
