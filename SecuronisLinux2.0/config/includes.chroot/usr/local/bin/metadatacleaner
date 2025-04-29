#!/usr/bin/env python3
import sys
import os
import traceback
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                           QVBoxLayout, QHBoxLayout, QWidget, QFileDialog, 
                           QProgressBar, QTextEdit, QMessageBox, QComboBox,
                           QMenuBar, QMenu, QAction, QStatusBar, QTabWidget,
                           QCheckBox, QStyle, QActionGroup, QRadioButton, QButtonGroup,
                           QSplitter, QFrame, QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QSize, QTimer
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor, QTextCursor
from PIL import Image
import piexif
import json
import threading

# Theme styles for the Metadata Cleaner application

# Dark Blue Theme (Default)
DARK_BLUE = """
QMainWindow {
    background-color: #1e1e2e;
    color: #ffffff;
}

QWidget {
    background-color: #1e1e2e;
    color: #ffffff;
}

QPushButton {
    background-color: #2d2d3f;
    color: #ffffff;
    border: 1px solid #3d3d5c;
    border-radius: 4px;
    padding: 6px 12px;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #3d3d5c;
}

QPushButton:pressed {
    background-color: #4d4d6c;
}

QPushButton:disabled {
    background-color: #2d2d3f;
    color: #888888;
}

QPushButton:checked {
    background-color: #4d4d6c;
    border: 1px solid #6d6d8c;
}

QLabel {
    color: #ffffff;
}

QProgressBar {
    border: 1px solid #3d3d5c;
    border-radius: 4px;
    text-align: center;
    background-color: #2d2d3f;
}

QProgressBar::chunk {
    background-color: #4d4d6c;
}

QTextEdit {
    background-color: #2d2d3f;
    color: #ffffff;
    border: 1px solid #3d3d5c;
    border-radius: 4px;
}

QFileDialog {
    background-color: #1e1e2e;
    color: #ffffff;
}

QMessageBox {
    background-color: #1e1e2e;
    color: #ffffff;
}

QMenuBar {
    background-color: #1e1e2e;
    color: #ffffff;
}

QMenuBar::item {
    background-color: #1e1e2e;
    color: #ffffff;
    padding: 4px 8px;
}

QMenuBar::item:selected {
    background-color: #3d3d5c;
}

QMenu {
    background-color: #1e1e2e;
    color: #ffffff;
    border: 1px solid #3d3d5c;
}

QMenu::item {
    background-color: #1e1e2e;
    color: #ffffff;
    padding: 4px 20px;
}

QMenu::item:selected {
    background-color: #3d3d5c;
}

QMenu::separator {
    height: 1px;
    background-color: #3d3d5c;
}

QStatusBar {
    background-color: #1e1e2e;
    color: #ffffff;
}

QTabWidget::pane {
    border: 1px solid #3d3d5c;
    background-color: #1e1e2e;
}

QTabBar::tab {
    background-color: #2d2d3f;
    color: #ffffff;
    border: 1px solid #3d3d5c;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 6px 12px;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background-color: #4d4d6c;
}

QTabBar::tab:hover {
    background-color: #3d3d5c;
}

QComboBox {
    background-color: #2d2d3f;
    color: #ffffff;
    border: 1px solid #3d3d5c;
    border-radius: 4px;
    padding: 4px 8px;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid #ffffff;
    border-top: 4px solid #ffffff;
    border-right: 0px solid transparent;
    border-bottom: 0px solid transparent;
    transform: rotate(-45deg);
    width: 8px;
    height: 8px;
}

QComboBox QAbstractItemView {
    background-color: #2d2d3f;
    color: #ffffff;
    border: 1px solid #3d3d5c;
    selection-background-color: #4d4d6c;
    selection-color: #ffffff;
}

QToolBar {
    background-color: #1e1e2e;
    border: none;
    spacing: 3px;
    padding: 3px;
}

QToolBar QToolButton {
    background-color: #2d2d3f;
    color: #ffffff;
    border: 1px solid #3d3d5c;
    border-radius: 4px;
    padding: 4px;
}

QToolBar QToolButton:hover {
    background-color: #3d3d5c;
}

QToolBar QToolButton:pressed {
    background-color: #4d4d6c;
}

QCheckBox {
    color: #ffffff;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #3d3d5c;
    border-radius: 3px;
    background-color: #2d2d3f;
}

QCheckBox::indicator:checked {
    background-color: #4d4d6c;
    border: 1px solid #6d6d8c;
    image: url(check.png);
}

QCheckBox::indicator:hover {
    background-color: #3d3d5c;
}
"""

# Light Theme
LIGHT = """
QMainWindow {
    background-color: #f5f5f5;
    color: #333333;
}

QWidget {
    background-color: #f5f5f5;
    color: #333333;
}

QPushButton {
    background-color: #e0e0e0;
    color: #333333;
    border: 1px solid #cccccc;
    border-radius: 4px;
    padding: 6px 12px;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #d0d0d0;
}

QPushButton:pressed {
    background-color: #c0c0c0;
}

QPushButton:disabled {
    background-color: #e0e0e0;
    color: #888888;
}

QPushButton:checked {
    background-color: #c0c0c0;
    border: 1px solid #a0a0a0;
}

QLabel {
    color: #333333;
}

QProgressBar {
    border: 1px solid #cccccc;
    border-radius: 4px;
    text-align: center;
    background-color: #e0e0e0;
}

QProgressBar::chunk {
    background-color: #c0c0c0;
}

QTextEdit {
    background-color: #ffffff;
    color: #333333;
    border: 1px solid #cccccc;
    border-radius: 4px;
}

QFileDialog {
    background-color: #f5f5f5;
    color: #333333;
}

QMessageBox {
    background-color: #f5f5f5;
    color: #333333;
}

QMenuBar {
    background-color: #f5f5f5;
    color: #333333;
}

QMenuBar::item {
    background-color: #f5f5f5;
    color: #333333;
    padding: 4px 8px;
}

QMenuBar::item:selected {
    background-color: #d0d0d0;
}

QMenu {
    background-color: #f5f5f5;
    color: #333333;
    border: 1px solid #cccccc;
}

QMenu::item {
    background-color: #f5f5f5;
    color: #333333;
    padding: 4px 20px;
}

QMenu::item:selected {
    background-color: #d0d0d0;
}

QMenu::separator {
    height: 1px;
    background-color: #cccccc;
}

QStatusBar {
    background-color: #f5f5f5;
    color: #333333;
}

QTabWidget::pane {
    border: 1px solid #cccccc;
    background-color: #f5f5f5;
}

QTabBar::tab {
    background-color: #e0e0e0;
    color: #333333;
    border: 1px solid #cccccc;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 6px 12px;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background-color: #c0c0c0;
}

QTabBar::tab:hover {
    background-color: #d0d0d0;
}

QComboBox {
    background-color: #e0e0e0;
    color: #333333;
    border: 1px solid #cccccc;
    border-radius: 4px;
    padding: 4px 8px;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid #333333;
    border-top: 4px solid #333333;
    border-right: 0px solid transparent;
    border-bottom: 0px solid transparent;
    transform: rotate(-45deg);
    width: 8px;
    height: 8px;
}

QComboBox QAbstractItemView {
    background-color: #e0e0e0;
    color: #333333;
    border: 1px solid #cccccc;
    selection-background-color: #c0c0c0;
    selection-color: #333333;
}

QToolBar {
    background-color: #f5f5f5;
    border: none;
    spacing: 3px;
    padding: 3px;
}

QToolBar QToolButton {
    background-color: #e0e0e0;
    color: #333333;
    border: 1px solid #cccccc;
    border-radius: 4px;
    padding: 4px;
}

QToolBar QToolButton:hover {
    background-color: #d0d0d0;
}

QToolBar QToolButton:pressed {
    background-color: #c0c0c0;
}

QCheckBox {
    color: #333333;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #cccccc;
    border-radius: 3px;
    background-color: #e0e0e0;
}

QCheckBox::indicator:checked {
    background-color: #c0c0c0;
    border: 1px solid #a0a0a0;
    image: url(check.png);
}

QCheckBox::indicator:hover {
    background-color: #d0d0d0;
}
"""

# Dark Theme
DARK = """
QMainWindow {
    background-color: #121212;
    color: #ffffff;
}

QWidget {
    background-color: #121212;
    color: #ffffff;
}

QPushButton {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 1px solid #333333;
    border-radius: 4px;
    padding: 6px 12px;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #333333;
}

QPushButton:pressed {
    background-color: #444444;
}

QPushButton:disabled {
    background-color: #1e1e1e;
    color: #888888;
}

QPushButton:checked {
    background-color: #444444;
    border: 1px solid #555555;
}

QLabel {
    color: #ffffff;
}

QProgressBar {
    border: 1px solid #333333;
    border-radius: 4px;
    text-align: center;
    background-color: #1e1e1e;
}

QProgressBar::chunk {
    background-color: #444444;
}

QTextEdit {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 1px solid #333333;
    border-radius: 4px;
}

QFileDialog {
    background-color: #121212;
    color: #ffffff;
}

QMessageBox {
    background-color: #121212;
    color: #ffffff;
}

QMenuBar {
    background-color: #121212;
    color: #ffffff;
}

QMenuBar::item {
    background-color: #121212;
    color: #ffffff;
    padding: 4px 8px;
}

QMenuBar::item:selected {
    background-color: #333333;
}

QMenu {
    background-color: #121212;
    color: #ffffff;
    border: 1px solid #333333;
}

QMenu::item {
    background-color: #121212;
    color: #ffffff;
    padding: 4px 20px;
}

QMenu::item:selected {
    background-color: #333333;
}

QMenu::separator {
    height: 1px;
    background-color: #333333;
}

QStatusBar {
    background-color: #121212;
    color: #ffffff;
}

QTabWidget::pane {
    border: 1px solid #333333;
    background-color: #121212;
}

QTabBar::tab {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 1px solid #333333;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 6px 12px;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background-color: #444444;
}

QTabBar::tab:hover {
    background-color: #333333;
}

QComboBox {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 1px solid #333333;
    border-radius: 4px;
    padding: 4px 8px;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid #ffffff;
    border-top: 4px solid #ffffff;
    border-right: 0px solid transparent;
    border-bottom: 0px solid transparent;
    transform: rotate(-45deg);
    width: 8px;
    height: 8px;
}

QComboBox QAbstractItemView {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 1px solid #333333;
    selection-background-color: #444444;
    selection-color: #ffffff;
}

QToolBar {
    background-color: #121212;
    border: none;
    spacing: 3px;
    padding: 3px;
}

QToolBar QToolButton {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 1px solid #333333;
    border-radius: 4px;
    padding: 4px;
}

QToolBar QToolButton:hover {
    background-color: #333333;
}

QToolBar QToolButton:pressed {
    background-color: #444444;
}

QCheckBox {
    color: #ffffff;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #333333;
    border-radius: 3px;
    background-color: #1e1e1e;
}

QCheckBox::indicator:checked {
    background-color: #444444;
    border: 1px solid #555555;
    image: url(check.png);
}

QCheckBox::indicator:hover {
    background-color: #333333;
}
"""

# Theme dictionary
THEMES = {
    "Dark Blue": DARK_BLUE,
    "Light": LIGHT,
    "Dark": DARK
}

# Supported image formats
SUPPORTED_FORMATS = [
    '.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif', '.webp', 
    '.tif', '.ico', '.svg', '.heic', '.heif', '.raw', '.cr2', 
    '.nef', '.arw', '.dng', '.psd', '.ai', '.eps'
]

# Maximum file size for processing (in MB)
MAX_FILE_SIZE = 100

class MetadataCleanerThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, path, is_folder=False, recursive=False, clean_metadata=False):
        super().__init__()
        self.path = path
        self.is_folder = is_folder
        self.recursive = recursive
        self.clean_metadata = clean_metadata
        self._stop_event = threading.Event()
        self._stop_event.clear()

    def stop(self):
        self._stop_event.set()
        self.status.emit("Stopping...")

    def run(self):
        try:
            results = []
            
            # Get all image files
            if self.is_folder:
                if self.recursive:
                    files = []
                    for root, _, filenames in os.walk(self.path):
                        if self._stop_event.is_set():
                            break
                        for filename in filenames:
                            if any(filename.lower().endswith(fmt) for fmt in SUPPORTED_FORMATS):
                                files.append(os.path.join(root, filename))
                else:
                    files = [os.path.join(self.path, f) for f in os.listdir(self.path) 
                            if any(f.lower().endswith(fmt) for fmt in SUPPORTED_FORMATS)]
            else:
                # Single file
                files = [self.path]
            
            total_files = len(files)
            
            if total_files == 0:
                self.error.emit("No supported image files found.")
                return

            self.status.emit(f"Found {total_files} files to process")
            
            for i, file_path in enumerate(files):
                if self._stop_event.is_set():
                    self.status.emit("Processing stopped by user")
                    break
                    
                try:
                    # Check file size
                    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                    if file_size_mb > MAX_FILE_SIZE:
                        self.status.emit(f"Skipping large file: {os.path.basename(file_path)} ({file_size_mb:.2f} MB)")
                        continue
                    
                    self.status.emit(f"Processing: {os.path.basename(file_path)}")
                    
                    # Open image
                    img = Image.open(file_path)
                    
                    # Get EXIF data
                    exif_dict = {}
                    try:
                        if "exif" in img.info:
                            exif_dict = piexif.load(img.info["exif"])
                    except Exception as exif_error:
                        exif_dict = {"error": str(exif_error)}
                    
                    # Get all metadata
                    metadata = {}
                    for key, value in img.info.items():
                        if key != "exif":  # Exif is handled separately
                            metadata[key] = str(value)
                    
                    # Clean metadata if requested
                    metadata_cleaning = {"cleaned": False}
                    
                    if self.clean_metadata:
                        try:
                            # Remove metadata: use piexif.remove for JPEG/TIFF, fallback for others
                            if img.format in ("JPEG", "TIFF"):
                                piexif.remove(file_path)
                            else:
                                new_img = Image.new(img.mode, img.size)
                                new_img.putdata(list(img.getdata()))
                                new_img.save(file_path, format=img.format, quality=95)
                            metadata_cleaning = {"cleaned": True}
                            self.status.emit(f"Metadata cleaned: {os.path.basename(file_path)}")
                        except Exception as clean_error:
                            metadata_cleaning = {
                                "error": str(clean_error),
                                "cleaned": False
                            }
                            self.error.emit(f"Error cleaning metadata for {os.path.basename(file_path)}: {str(clean_error)}")
                    
                    # Collect metadata information
                    file_info = {
                        "file": os.path.basename(file_path),
                        "path": file_path,
                        "size": f"{os.path.getsize(file_path) / 1024:.2f} KB",
                        "format": img.format,
                        "mode": img.mode,
                        "exif": exif_dict,
                        "metadata": metadata,
                        "metadata_cleaning": metadata_cleaning
                    }
                    
                    results.append(file_info)
                    
                except Exception as e:
                    self.error.emit(f"Error processing {os.path.basename(file_path)}: {str(e)}")
                
                self.progress.emit(int((i + 1) / total_files * 100))
            
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(f"General error: {str(e)}\n{traceback.format_exc()}")

class MetadataCleaner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Metadata Cleaner")
        self.setGeometry(100, 100, 1000, 800)
        
        # Load settings
        self.settings = QSettings("MetadataCleaner", "Settings")
        self.current_theme = self.settings.value("theme", "Dark Blue")
        self.last_directory = self.settings.value("last_directory", "")
        
        # Create menu bar
        self.create_menu_bar()
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Top section - Path selection
        top_layout = QHBoxLayout()
        self.path_label = QLabel("Selected Path: None")
        self.path_label.setMinimumWidth(400)
        self.select_path_btn = QPushButton("Select Path")
        self.select_path_btn.clicked.connect(self.select_path)
        top_layout.addWidget(self.path_label)
        top_layout.addWidget(self.select_path_btn)
        layout.addLayout(top_layout)
        
        # Selection type
        selection_layout = QHBoxLayout()
        self.selection_group = QButtonGroup(self)
        
        self.folder_radio = QRadioButton("Folder")
        self.folder_radio.setChecked(True)
        self.selection_group.addButton(self.folder_radio)
        
        self.file_radio = QRadioButton("File")
        self.selection_group.addButton(self.file_radio)
        
        selection_layout.addWidget(self.folder_radio)
        selection_layout.addWidget(self.file_radio)
        selection_layout.addStretch()
        layout.addLayout(selection_layout)
        
        # Options section
        options_layout = QHBoxLayout()
        self.recursive_checkbox = QCheckBox("Scan Subfolders")
        self.recursive_checkbox.setChecked(True)
        self.recursive_checkbox.setEnabled(True)
        self.recursive_checkbox.setStyleSheet("""
            QCheckBox {
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: none;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                image: url(/usr/share/securonis/icons/tick.png);
            }
            QCheckBox::indicator:unchecked {
                image: none;
            }
            QCheckBox::indicator:hover {
                background-color: rgba(76, 175, 80, 0.1);
            }
        """)
        
        # Metadata cleaning option
        self.clean_metadata_checkbox = QCheckBox("Clean Metadata")
        self.clean_metadata_checkbox.setChecked(True)
        self.clean_metadata_checkbox.setToolTip("Remove all metadata from images")
        self.clean_metadata_checkbox.setStyleSheet("""
            QCheckBox {
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: none;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                image: url(/usr/share/securonis/icons/tick.png);
            }
            QCheckBox::indicator:unchecked {
                image: none;
            }
            QCheckBox::indicator:hover {
                background-color: rgba(76, 175, 80, 0.1);
            }
        """)
        
        options_layout.addWidget(self.recursive_checkbox)
        options_layout.addWidget(self.clean_metadata_checkbox)
        options_layout.addStretch()
        layout.addLayout(options_layout)
        
        # Connect radio buttons to update recursive checkbox state
        self.folder_radio.toggled.connect(self.update_recursive_state)
        self.file_radio.toggled.connect(self.update_recursive_state)
        
        # Progress section
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% (%v/%m)")
        
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_processing)
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.stop_btn)
        layout.addLayout(progress_layout)
        
        # Status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        # Tab widget for results
        self.tab_widget = QTabWidget()
        
        # Text tab
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.tab_widget.addTab(self.results_text, "Text View")
        
        # JSON tab
        self.json_text = QTextEdit()
        self.json_text.setReadOnly(True)
        self.tab_widget.addTab(self.json_text, "JSON View")
        
        layout.addWidget(self.tab_widget)
        
        # Bottom section - Buttons
        bottom_layout = QHBoxLayout()
        self.clean_btn = QPushButton("Clean Metadata")
        self.clean_btn.clicked.connect(self.clean_metadata)
        
        self.save_btn = QPushButton("Save as JSON")
        self.save_btn.clicked.connect(self.save_results)
        self.save_btn.setEnabled(False)
        
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        self.clear_btn.setEnabled(False)
        
        bottom_layout.addWidget(self.clean_btn)
        bottom_layout.addWidget(self.save_btn)
        bottom_layout.addWidget(self.clear_btn)
        layout.addLayout(bottom_layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        self.selected_path = None
        self.current_results = None
        self.thread = None
        
        # Set window icon
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        # Set focus policy
        self.setFocusPolicy(Qt.StrongFocus)
        
        # Connect tab change event
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        
        # Apply theme after all UI components are created
        self.apply_theme(self.current_theme)

    def update_recursive_state(self):
        # Enable recursive checkbox only when folder is selected
        self.recursive_checkbox.setEnabled(self.folder_radio.isChecked())

    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # Theme menu
        theme_menu = menubar.addMenu("Theme")
        
        # Create a QActionGroup to ensure only one theme can be selected at a time
        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)
        
        for theme_name in THEMES.keys():
            theme_action = QAction(theme_name, self)
            theme_action.setCheckable(True)
            if theme_name == self.current_theme:
                theme_action.setChecked(True)
            theme_action.triggered.connect(lambda checked, tn=theme_name: self.apply_theme(tn))
            theme_group.addAction(theme_action)
            theme_menu.addAction(theme_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        # Add separator
        help_menu.addSeparator()
        
        # Add supported formats action
        formats_action = QAction("Supported Formats", self)
        formats_action.triggered.connect(self.show_supported_formats)
        help_menu.addAction(formats_action)

    def apply_theme(self, theme_name):
        try:
            self.current_theme = theme_name
            self.settings.setValue("theme", theme_name)
            self.setStyleSheet(THEMES[theme_name])
            
            # Update status bar
            self.status_bar.showMessage(f"Theme changed: {theme_name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to apply theme: {str(e)}")

    def show_about(self):
        formats_str = ", ".join([fmt[1:] for fmt in SUPPORTED_FORMATS])
        QMessageBox.about(self, "About Metadata Cleaner",
                         "Metadata Cleaner v1.3\n\n"
                         "A tool for cleaning metadata from image files.\n\n"
                         f"Supported formats: {formats_str}\n\n"
                         "Maximum file size: 100 MB\n\n"
                         "Features:\n"
                         "- Clean metadata from images\n"
                         "- Batch process folders")

    def show_supported_formats(self):
        formats_str = "\n".join([f"- {fmt[1:]}" for fmt in SUPPORTED_FORMATS])
        QMessageBox.information(self, "Supported Formats",
                              f"The following image formats are supported:\n\n{formats_str}")

    def select_path(self):
        try:
            if self.folder_radio.isChecked():
                path = QFileDialog.getExistingDirectory(
                    self, "Select Folder", self.last_directory)
            else:
                # Create filter string for all supported formats
                filter_str = "Image Files ("
                for fmt in SUPPORTED_FORMATS:
                    filter_str += f"*{fmt} "
                filter_str += ")"
                
                path, _ = QFileDialog.getOpenFileName(
                    self, "Select Image File", self.last_directory, filter_str)
            
            if path:
                self.selected_path = path
                self.path_label.setText(f"Selected Path: {path}")
                self.status_bar.showMessage(f"Path selected: {path}")
                
                # Save last directory
                if os.path.isdir(path):
                    self.last_directory = path
                else:
                    self.last_directory = os.path.dirname(path)
                self.settings.setValue("last_directory", self.last_directory)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to select path: {str(e)}")

    def clean_metadata(self):
        if not self.selected_path:
            QMessageBox.warning(self, "Warning", "Please select a path!")
            return
        
        try:
            self.clean_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setValue(0)
            self.results_text.clear()
            self.json_text.clear()
            self.status_bar.showMessage("Processing...")
            
            is_folder = self.folder_radio.isChecked()
            recursive = is_folder and self.recursive_checkbox.isChecked()
            clean_metadata = self.clean_metadata_checkbox.isChecked()
            
            self.thread = MetadataCleanerThread(
                self.selected_path, 
                is_folder=is_folder,
                recursive=recursive,
                clean_metadata=clean_metadata
            )
            self.thread.progress.connect(self.update_progress)
            self.thread.finished.connect(self.process_results)
            self.thread.error.connect(self.show_error)
            self.thread.status.connect(self.update_status)
            self.thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start processing: {str(e)}")
            self.clean_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_bar.showMessage("Error occurred")

    def stop_processing(self):
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.stop_btn.setEnabled(False)
            self.status_bar.showMessage("Stopping...")

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        self.status_bar.showMessage(f"Processing... {value}%")

    def update_status(self, message):
        self.status_label.setText(message)
        self.status_bar.showMessage(message)

    def process_results(self, results):
        try:
            self.current_results = results
            self.clean_btn.setEnabled(True)
            self.save_btn.setEnabled(True)
            self.clear_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
            if not results:
                self.status_bar.showMessage("No results to display")
                return
            
            # Display results in text view
            text = "Metadata Cleaning Results:\n\n"
            for result in results:
                text += f"File: {result['file']}\n"
                text += f"Path: {result['path']}\n"
                text += f"Size: {result['size']}\n"
                
                # Add metadata cleaning results
                if result['metadata_cleaning'].get('cleaned', False):
                    text += "\nMetadata successfully cleaned.\n"
                else:
                    text += "\nFailed to clean metadata.\n"
            
            self.results_text.setText(text)
            
            # Display results in JSON view
            json_text = json.dumps(results, indent=2, ensure_ascii=False)
            self.json_text.setText(json_text)
            
            self.status_bar.showMessage(f"Completed. {len(results)} files processed.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to process results: {str(e)}")
            self.status_bar.showMessage("Error processing results")

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.status_bar.showMessage("Error occurred")

    def save_results(self):
        if not self.current_results:
            return
            
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save JSON", "", "JSON Files (*.json)")
                
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.current_results, f, ensure_ascii=False, indent=2)
                QMessageBox.information(self, "Success", 
                    "Results saved successfully!")
                self.status_bar.showMessage(f"Results saved: {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", 
                f"Failed to save file: {str(e)}")
            self.status_bar.showMessage("Error saving results")

    def clear_results(self):
        self.results_text.clear()
        self.json_text.clear()
        self.current_results = None
        self.save_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.status_bar.showMessage("Results cleared")

    def on_tab_changed(self, index):
        # Auto-scroll to the end when switching tabs
        if index == 0:  # Text tab
            cursor = self.results_text.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.results_text.setTextCursor(cursor)
        elif index == 1:  # JSON tab
            cursor = self.json_text.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.json_text.setTextCursor(cursor)

    def closeEvent(self, event):
        # Stop any running thread
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.thread.wait(1000)  # Wait up to 1 second for thread to finish
        
        # Save settings before closing
        self.settings.sync()
        event.accept()

if __name__ == '__main__':
    # Set up exception handling
    def exception_hook(exctype, value, traceback_obj):
        error_msg = ''.join(traceback.format_exception(exctype, value, traceback_obj))
        QMessageBox.critical(None, "Unhandled Exception", error_msg)
    
    sys.excepthook = exception_hook
    
    app = QApplication(sys.argv)
    window = MetadataCleaner()
    window.show()
    sys.exit(app.exec_())
