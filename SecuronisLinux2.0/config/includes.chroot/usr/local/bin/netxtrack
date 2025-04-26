#!/usr/bin/env python3
# DEVELOPER: root0emir 
import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QComboBox, 
                           QTableWidget, QTableWidgetItem, QTextEdit, QFileDialog,
                           QMenu, QAction, QStatusBar, QSplitter, QTabWidget,
                           QToolBar, QStyle, QDockWidget, QListWidget, QGroupBox,
                           QFormLayout, QSpinBox, QCheckBox, QProgressBar, QMessageBox,
                           QDialog, QLineEdit, QDialogButtonBox, QTreeWidget, QTreeWidgetItem,
                           QHeaderView, QStyleFactory, QSystemTrayIcon, QMenuBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt5.QtGui import QIcon, QColor, QFont, QPalette, QBrush, QLinearGradient
import scapy.all as scapy
import pandas as pd
import numpy as np
from datetime import datetime
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from collections import defaultdict
import networkx as nx
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNSQR, DNSRR
import threading
import queue
import time
from scapy.utils import wrpcap, rdpcap
import csv
import re
import socket
import psutil

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(list)
    stats_updated = pyqtSignal(dict)
    traffic_updated = pyqtSignal(dict)
    alert_triggered = pyqtSignal(dict)
    
    def __init__(self, interface, filter_text="", promiscuous=False, buffer_size=1000, timeout=0):
        super().__init__()
        self.interface = interface
        self.filter_text = filter_text
        self.promiscuous = promiscuous
        self.buffer_size = buffer_size
        self.timeout = timeout
        self.is_running = True
        self.stats = defaultdict(int)
        self.traffic_data = {
            'timestamps': [],
            'packet_counts': [],
            'byte_counts': [],
            'protocol_counts': defaultdict(int)
        }
        self.start_time = datetime.now()
        self.packet_queue = queue.Queue()
        self.alert_rules = []
        self.packet_buffer = []
        self.last_update = time.time()
        self.update_interval = 0.5
        
    def run(self):
        self.processor_thread = threading.Thread(target=self.process_packets)
        self.processor_thread.start()
        
        scapy.sniff(iface=self.interface, 
                   prn=self.queue_packet,
                   store=False,
                   filter=self.filter_text,
                   promisc=self.promiscuous)
        
    def queue_packet(self, packet):
        if not self.is_running:
            return
        self.packet_queue.put(packet)
        
    def process_packets(self):
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=0.1)
                packet_info = self.process_packet(packet)
                self.packet_buffer.append(packet_info)
                
                # Check alert rules
                self.check_alert_rules(packet_info)
                
                current_time = time.time()
                if len(self.packet_buffer) >= self.buffer_size or (current_time - self.last_update) >= self.update_interval:
                    self.flush_buffer()
                    self.last_update = current_time
                    
            except queue.Empty:
                continue
                
    def process_packet(self, packet):
        packet_info = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'source': packet[IP].src if IP in packet else 'N/A',
            'destination': packet[IP].dst if IP in packet else 'N/A',
            'protocol': self.get_protocol_name(packet),
            'length': len(packet),
            'type': self.get_packet_type(packet),
            'raw': bytes(packet),  # Store raw packet data for PCAP export
            'details': {}  # Initialize details dictionary
        }
        
        # Extract detailed packet information
        if IP in packet:
            proto = packet[IP].proto
            self.stats[proto] += 1
            packet_info['details']['ip'] = {
                'version': packet[IP].version,
                'ihl': packet[IP].ihl,
                'tos': packet[IP].tos,
                'len': packet[IP].len,
                'id': packet[IP].id,
                'ttl': packet[IP].ttl,
                'proto': packet[IP].proto
            }
            
        if TCP in packet:
            packet_info['details']['tcp'] = {
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack,
                'flags': packet[TCP].flags
            }
            
        if UDP in packet:
            packet_info['details']['udp'] = {
                'sport': packet[UDP].sport,
                'dport': packet[UDP].dport,
                'len': packet[UDP].len
            }
            
        if ICMP in packet:
            packet_info['details']['icmp'] = {
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            }
            
        if ARP in packet:
            packet_info['details']['arp'] = {
                'hwtype': packet[ARP].hwtype,
                'ptype': packet[ARP].ptype,
                'hwsrc': packet[ARP].hwsrc,
                'psrc': packet[ARP].psrc,
                'hwdst': packet[ARP].hwdst,
                'pdst': packet[ARP].pdst
            }
            
        current_time = (datetime.now() - self.start_time).total_seconds()
        self.traffic_data['timestamps'].append(current_time)
        self.traffic_data['packet_counts'].append(len(self.traffic_data['packet_counts']) + 1)
        self.traffic_data['byte_counts'].append(len(packet))
        self.traffic_data['protocol_counts'][packet_info['protocol']] += 1
        
        return packet_info
        
    def flush_buffer(self):
        if self.packet_buffer:
            self.packet_captured.emit(self.packet_buffer.copy())
            self.stats_updated.emit(dict(self.stats))
            self.traffic_updated.emit(self.traffic_data)
            self.packet_buffer.clear()
            
    def get_protocol_name(self, packet):
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        elif ARP in packet:
            return 'ARP'
        elif IP in packet:
            return f'IP ({packet[IP].proto})'
        return 'Unknown'
        
    def get_packet_type(self, packet):
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        elif ARP in packet:
            return 'ARP'
        return 'Other'
    
    def add_alert_rule(self, rule):
        self.alert_rules.append(rule)
        
    def check_alert_rules(self, packet_info):
        for rule in self.alert_rules:
            if not rule['enabled']:
                continue
                
            match = False
            
            if rule['type'] == 'protocol' and packet_info['protocol'] == rule['value']:
                match = True
            elif rule['type'] == 'source' and packet_info['source'] == rule['value']:
                match = True
            elif rule['type'] == 'destination' and packet_info['destination'] == rule['value']:
                match = True
            elif rule['type'] == 'port' and 'tcp' in packet_info['details']:
                if str(packet_info['details']['tcp']['sport']) == rule['value'] or str(packet_info['details']['tcp']['dport']) == rule['value']:
                    match = True
            elif rule['type'] == 'port' and 'udp' in packet_info['details']:
                if str(packet_info['details']['udp']['sport']) == rule['value'] or str(packet_info['details']['udp']['dport']) == rule['value']:
                    match = True
                    
            if match:
                alert = {
                    'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'rule': rule['name'],
                    'packet': packet_info
                }
                self.alert_triggered.emit(alert)
        
    def stop(self):
        self.is_running = False
        if hasattr(self, 'processor_thread'):
            self.processor_thread.join()

class AlertRuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Alert Rule")
        self.setup_ui()
        
    def setup_ui(self):
        layout = QFormLayout(self)
        
        self.name_edit = QLineEdit()
        layout.addRow("Rule Name:", self.name_edit)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(['protocol', 'source', 'destination', 'port'])
        layout.addRow("Rule Type:", self.type_combo)
        
        self.value_edit = QLineEdit()
        layout.addRow("Value:", self.value_edit)
        
        self.enabled_check = QCheckBox("Enabled")
        self.enabled_check.setChecked(True)
        layout.addRow(self.enabled_check)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            Qt.Horizontal, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        
    def get_rule(self):
        return {
            'name': self.name_edit.text(),
            'type': self.type_combo.currentText(),
            'value': self.value_edit.text(),
            'enabled': self.enabled_check.isChecked()
        }

class Netxtrack(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Netxtrack - Advanced Network Packet Analyzer")
        self.setGeometry(100, 100, 1800, 1200)
        
        # Set modern style
        self.setStyle(QStyleFactory.create('Fusion'))
        
        # Initialize data structures
        self.packets = []
        self.capture_thread = None
        self.current_file = None
        self.filter_history = []
        self.alert_rules = []
        self.stats = defaultdict(int)  # Initialize stats attribute
        self.protocol_colors = {
            'TCP': QColor(0, 128, 255),
            'UDP': QColor(0, 255, 128),
            'ICMP': QColor(255, 128, 0),
            'HTTP': QColor(255, 0, 128),
            'DNS': QColor(128, 0, 255),
            'ARP': QColor(255, 255, 0),
            'Other': QColor(128, 128, 128)
        }
        
        # Performance optimization
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(500)  # 500ms aralıklarla güncelle
        
        # Create system tray icon
        self.create_system_tray()
        
        self.init_ui()
        
    def create_system_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        tray_menu = QMenu()
        show_action = tray_menu.addAction("Show")
        show_action.triggered.connect(self.show)
        hide_action = tray_menu.addAction("Hide")
        hide_action.triggered.connect(self.hide)
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(QApplication.quit)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
    def init_ui(self):
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create tool bar
        self.create_tool_bar()
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        # Create dock widgets
        self.create_dock_widgets()
        
        # Create control panel
        control_layout = QHBoxLayout()
        
        # Interface selection
        interface_group = QGroupBox("Interface Settings")
        interface_layout = QFormLayout()
        
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(scapy.get_if_list())
        interface_layout.addRow("Interface:", self.interface_combo)
        
        self.promiscuous_check = QCheckBox("Promiscuous Mode")
        interface_layout.addRow(self.promiscuous_check)
        
        interface_group.setLayout(interface_layout)
        control_layout.addWidget(interface_group)
        
        # Capture settings
        capture_group = QGroupBox("Capture Settings")
        capture_layout = QFormLayout()
        
        self.buffer_size = QSpinBox()
        self.buffer_size.setRange(100, 10000)
        self.buffer_size.setValue(1000)
        capture_layout.addRow("Buffer Size:", self.buffer_size)
        
        self.timeout = QSpinBox()
        self.timeout.setRange(0, 3600)
        self.timeout.setValue(0)
        capture_layout.addRow("Timeout (s):", self.timeout)
        
        capture_group.setLayout(capture_layout)
        control_layout.addWidget(capture_group)
        
        # Filter settings
        filter_group = QGroupBox("Filter Settings")
        filter_layout = QFormLayout()
        
        self.filter_input = QTextEdit()
        self.filter_input.setMaximumHeight(30)
        self.filter_input.setPlaceholderText("Enter filter (e.g., tcp port 80)")
        filter_layout.addRow("Filter:", self.filter_input)
        
        self.filter_history_list = QListWidget()
        self.filter_history_list.setMaximumHeight(100)
        filter_layout.addRow("Filter History:", self.filter_history_list)
        
        filter_group.setLayout(filter_layout)
        control_layout.addWidget(filter_group)
        
        layout.addLayout(control_layout)
        
        # Create main content area
        splitter = QSplitter(Qt.Vertical)
        
        # Create tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Packet table tab
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Type', 'Details'])
        self.packet_table.itemClicked.connect(self.show_packet_details)
        self.tab_widget.addTab(self.packet_table, "Packets")
        
        # Statistics tab
        self.stats_widget = QWidget()
        stats_layout = QVBoxLayout(self.stats_widget)
        
        # Protocol statistics
        self.protocol_canvas = FigureCanvas(plt.figure())
        stats_layout.addWidget(self.protocol_canvas)
        
        # Traffic statistics
        self.traffic_canvas = FigureCanvas(plt.figure())
        stats_layout.addWidget(self.traffic_canvas)
        
        self.tab_widget.addTab(self.stats_widget, "Statistics")
        
        # Network graph tab
        self.graph_widget = QWidget()
        graph_layout = QVBoxLayout(self.graph_widget)
        self.graph_canvas = FigureCanvas(plt.figure())
        graph_layout.addWidget(self.graph_canvas)
        self.tab_widget.addTab(self.graph_widget, "Network Graph")
        
        # Alerts tab
        self.alerts_widget = QWidget()
        alerts_layout = QVBoxLayout(self.alerts_widget)
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(4)
        self.alerts_table.setHorizontalHeaderLabels(['Time', 'Rule', 'Source', 'Destination'])
        alerts_layout.addWidget(self.alerts_table)
        self.tab_widget.addTab(self.alerts_widget, "Alerts")
        
        # Add tabs to splitter
        splitter.addWidget(self.tab_widget)
        
        # Packet details
        self.packet_details = QTreeWidget()
        self.packet_details.setHeaderLabels(['Field', 'Value'])
        splitter.addWidget(self.packet_details)
        
        # Set splitter sizes
        splitter.setSizes([600, 300])
        
        layout.addWidget(splitter)
        
        # Create progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
    def create_tool_bar(self):
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        # Start/Stop capture
        start_action = QAction(self.style().standardIcon(QStyle.SP_MediaPlay), "Start Capture", self)
        start_action.triggered.connect(self.start_capture)
        toolbar.addAction(start_action)
        
        stop_action = QAction(self.style().standardIcon(QStyle.SP_MediaStop), "Stop Capture", self)
        stop_action.triggered.connect(self.stop_capture)
        toolbar.addAction(stop_action)
        
        toolbar.addSeparator()
        
        # Save/Load
        save_action = QAction(self.style().standardIcon(QStyle.SP_DialogSaveButton), "Save Capture", self)
        save_action.triggered.connect(self.save_capture)
        toolbar.addAction(save_action)
        
        load_action = QAction(self.style().standardIcon(QStyle.SP_DialogOpenButton), "Open Capture", self)
        load_action.triggered.connect(self.open_capture)
        toolbar.addAction(load_action)
        
        toolbar.addSeparator()
        
        # Clear
        clear_action = QAction(self.style().standardIcon(QStyle.SP_TrashIcon), "Clear Capture", self)
        clear_action.triggered.connect(self.clear_capture)
        toolbar.addAction(clear_action)
        
        toolbar.addSeparator()
        
        # Alerts
        alert_action = QAction(self.style().standardIcon(QStyle.SP_MessageBoxWarning), "Add Alert Rule", self)
        alert_action.triggered.connect(self.add_alert_rule)
        toolbar.addAction(alert_action)
        
    def create_dock_widgets(self):
        # Protocol filter dock
        protocol_dock = QDockWidget("Protocol Filter", self)
        protocol_list = QListWidget()
        protocol_list.addItems(['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'ARP', 'Other'])
        protocol_dock.setWidget(protocol_list)
        self.addDockWidget(Qt.LeftDockWidgetArea, protocol_dock)
        
        # Capture info dock
        info_dock = QDockWidget("Capture Information", self)
        info_widget = QWidget()
        info_layout = QFormLayout()
        
        self.packet_count_label = QLabel("0")
        info_layout.addRow("Total Packets:", self.packet_count_label)
        
        self.byte_count_label = QLabel("0")
        info_layout.addRow("Total Bytes:", self.byte_count_label)
        
        self.duration_label = QLabel("00:00:00")
        info_layout.addRow("Duration:", self.duration_label)
        
        info_widget.setLayout(info_layout)
        info_dock.setWidget(info_widget)
        self.addDockWidget(Qt.RightDockWidgetArea, info_dock)
        
        # System info dock
        sys_dock = QDockWidget("System Information", self)
        sys_widget = QWidget()
        sys_layout = QFormLayout()
        
        self.cpu_label = QLabel("0%")
        sys_layout.addRow("CPU Usage:", self.cpu_label)
        
        self.memory_label = QLabel("0%")
        sys_layout.addRow("Memory Usage:", self.memory_label)
        
        self.network_label = QLabel("0 KB/s")
        sys_layout.addRow("Network Usage:", self.network_label)
        
        sys_widget.setLayout(sys_layout)
        sys_dock.setWidget(sys_widget)
        self.addDockWidget(Qt.RightDockWidgetArea, sys_dock)
        
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        new_action = QAction('New Capture', self)
        new_action.triggered.connect(self.new_capture)
        file_menu.addAction(new_action)
        
        open_action = QAction('Open Capture', self)
        open_action.triggered.connect(self.open_capture)
        file_menu.addAction(open_action)
        
        save_action = QAction('Save Capture', self)
        save_action.triggered.connect(self.save_capture)
        file_menu.addAction(save_action)
        
        export_menu = file_menu.addMenu('Export')
        export_pcap = QAction('Export as PCAP', self)
        export_pcap.triggered.connect(self.export_pcap)
        export_csv = QAction('Export as CSV', self)
        export_csv.triggered.connect(self.export_csv)
        export_menu.addAction(export_pcap)
        export_menu.addAction(export_csv)
        
        # Edit menu
        edit_menu = menubar.addMenu('Edit')
        
        clear_action = QAction('Clear Capture', self)
        clear_action.triggered.connect(self.clear_capture)
        edit_menu.addAction(clear_action)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        show_stats_action = QAction('Show Statistics', self)
        show_stats_action.triggered.connect(self.show_statistics)
        view_menu.addAction(show_stats_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        analyze_action = QAction('Analyze Traffic', self)
        analyze_action.triggered.connect(self.analyze_traffic)
        tools_menu.addAction(analyze_action)
        
        alert_action = QAction('Alert Rules', self)
        alert_action.triggered.connect(self.show_alert_rules)
        tools_menu.addAction(alert_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def start_capture(self):
        self.packets = []
        self.packet_table.setRowCount(0)
        filter_text = self.filter_input.toPlainText()
        self.capture_thread = PacketCaptureThread(
            self.interface_combo.currentText(),
            filter_text,
            self.promiscuous_check.isChecked(),
            self.buffer_size.value(),
            self.timeout.value()
        )
        self.capture_thread.packet_captured.connect(self.add_packet)
        self.capture_thread.stats_updated.connect(self.update_statistics)
        self.capture_thread.traffic_updated.connect(self.update_traffic)
        self.capture_thread.alert_triggered.connect(self.handle_alert)
        self.capture_thread.start()
        
        # Start timer for duration
        self.duration_timer = QTimer()
        self.duration_timer.timeout.connect(self.update_duration)
        self.duration_timer.start(1000)
        
        # Start system monitor timer
        self.sys_monitor_timer = QTimer()
        self.sys_monitor_timer.timeout.connect(self.update_system_info)
        self.sys_monitor_timer.start(2000)
        
        self.statusBar.showMessage("Capture started")
        
    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.duration_timer.stop()
            self.sys_monitor_timer.stop()
            self.statusBar.showMessage("Capture stopped")
            
    def add_packet(self, packet_list):
 
        start_row = self.packet_table.rowCount()
        self.packet_table.setRowCount(start_row + len(packet_list))
        
        for i, packet_info in enumerate(packet_list):
            row = start_row + i
            for col, key in enumerate(['timestamp', 'source', 'destination', 'protocol', 'length', 'type']):
                item = QTableWidgetItem(str(packet_info[key]))
                if key == 'type' and packet_info[key] in self.protocol_colors:
                    item.setBackground(self.protocol_colors[packet_info[key]])
                self.packet_table.setItem(row, col, item)
        
        self.packets.extend(packet_list)
        self.update_capture_info()
        
    def update_capture_info(self):
        total_packets = len(self.packets)
        total_bytes = sum(p['length'] for p in self.packets)
        
        self.packet_count_label.setText(str(total_packets))
        self.byte_count_label.setText(str(total_bytes))
        
    def update_duration(self):
        if self.capture_thread:
            duration = datetime.now() - self.capture_thread.start_time
            self.duration_label.setText(str(duration).split('.')[0])
            
    def update_system_info(self):
        self.cpu_label.setText(f"{psutil.cpu_percent()}%")
        self.memory_label.setText(f"{psutil.virtual_memory().percent}%")
        
        # Use non-blocking approach for network I/O measurement
        net_io = psutil.net_io_counters()
        
        if hasattr(self, 'last_net_io'):
            # Calculate difference since last measurement
            bytes_sent_diff = net_io.bytes_sent - self.last_net_io.bytes_sent
            bytes_recv_diff = net_io.bytes_recv - self.last_net_io.bytes_recv
            total_bytes = bytes_sent_diff + bytes_recv_diff
            
            # Update network usage label
            self.network_label.setText(f"{total_bytes/1024:.2f} KB/s")
        
        # Store current values for next measurement
        self.last_net_io = net_io
            
    def update_statistics(self, stats):

        if not hasattr(self, 'last_stats') or self.last_stats != stats:
            self.protocol_canvas.figure.clear()
            ax = self.protocol_canvas.figure.add_subplot(111)
            
            protocols = list(stats.keys())
            counts = list(stats.values())
            
            ax.pie(counts, labels=protocols, autopct='%1.1f%%')
            ax.set_title('Protocol Distribution')
            
            self.protocol_canvas.draw()
            self.last_stats = stats.copy()
            
    def update_traffic(self, traffic_data):

        if not hasattr(self, 'last_traffic') or self.last_traffic != traffic_data:
            self.traffic_canvas.figure.clear()
            ax = self.traffic_canvas.figure.add_subplot(111)
            
      
            timestamps = traffic_data['timestamps'][-100:]
            packet_counts = traffic_data['packet_counts'][-100:]
            byte_counts = traffic_data['byte_counts'][-100:]
            
            ax.plot(timestamps, packet_counts, label='Packets')
            ax.plot(timestamps, byte_counts, label='Bytes')
            
            ax.set_xlabel('Time (s)')
            ax.set_ylabel('Count')
            ax.set_title('Traffic Over Time')
            ax.legend()
            
            self.traffic_canvas.draw()
            self.last_traffic = traffic_data.copy()
            
    def show_packet_details(self, item):
        row = item.row()
        packet = self.packets[row]
        
        self.packet_details.clear()

        basic_info = QTreeWidgetItem(self.packet_details, ['Basic Information'])
        QTreeWidgetItem(basic_info, ['Time', packet['timestamp']])
        QTreeWidgetItem(basic_info, ['Source', packet['source']])
        QTreeWidgetItem(basic_info, ['Destination', packet['destination']])
        QTreeWidgetItem(basic_info, ['Protocol', packet['protocol']])
        QTreeWidgetItem(basic_info, ['Length', str(packet['length'])])
        

        if packet['details']:
            for proto, details in packet['details'].items():
                proto_item = QTreeWidgetItem(self.packet_details, [proto.upper()])
                for field, value in details.items():
                    QTreeWidgetItem(proto_item, [field, str(value)])
                    
        self.packet_details.expandAll()
        
    def analyze_traffic(self):

        G = nx.Graph()
        
        for packet in self.packets:
            if packet['source'] != 'N/A' and packet['destination'] != 'N/A':
                G.add_edge(packet['source'], packet['destination'])
                
        self.graph_canvas.figure.clear()
        ax = self.graph_canvas.figure.add_subplot(111)
        
        nx.draw(G, with_labels=True, ax=ax)
        ax.set_title('Network Communication Graph')
        
        self.graph_canvas.draw()
        
    def add_alert_rule(self):
        dialog = AlertRuleDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            rule = dialog.get_rule()
            self.alert_rules.append(rule)
            if self.capture_thread:
                self.capture_thread.add_alert_rule(rule)
                
    def handle_alert(self, alert):
        row = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row)
        
        self.alerts_table.setItem(row, 0, QTableWidgetItem(alert['timestamp']))
        self.alerts_table.setItem(row, 1, QTableWidgetItem(alert['rule']))
        self.alerts_table.setItem(row, 2, QTableWidgetItem(alert['packet']['source']))
        self.alerts_table.setItem(row, 3, QTableWidgetItem(alert['packet']['destination']))

        self.tray_icon.showMessage(
            "Alert Triggered",
            f"Rule: {alert['rule']}\nSource: {alert['packet']['source']}\nDestination: {alert['packet']['destination']}",
            QSystemTrayIcon.Warning
        )
        
    def show_alert_rules(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Alert Rules")
        layout = QVBoxLayout(dialog)
        
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(['Name', 'Type', 'Value', 'Enabled'])
        table.setRowCount(len(self.alert_rules))
        
        for i, rule in enumerate(self.alert_rules):
            table.setItem(i, 0, QTableWidgetItem(rule['name']))
            table.setItem(i, 1, QTableWidgetItem(rule['type']))
            table.setItem(i, 2, QTableWidgetItem(rule['value']))
            table.setItem(i, 3, QTableWidgetItem('Yes' if rule['enabled'] else 'No'))
            
        layout.addWidget(table)
        dialog.exec_()
        
    def show_about(self):
        about_text = """
        Netxtrack -  Network Packet Analyzer
        
        Version: 2.0
        Author: root0emir
        
        A powerful network packet analyzer with advanced features
        for network monitoring and analysis.
        
        Features:
        - Real-time packet capture
        - Protocol analysis
        - Traffic visualization
        - Alert system
        - System monitoring
        - Export capabilities
        """
        QMessageBox.about(self, "About Netxtrack", about_text)
        
    def new_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            reply = QMessageBox.question(self, 'New Capture',
                                       'A capture is currently running. Do you want to stop it and start a new one?',
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                return
            self.stop_capture()
        
        self.packets = []
        self.packet_table.setRowCount(0)
        self.alerts_table.setRowCount(0)
        self.filter_input.clear()
        self.current_file = None
        self.statusBar.showMessage("Ready for new capture")
        
    def open_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            reply = QMessageBox.question(self, 'Open Capture',
                                       'A capture is currently running. Do you want to stop it and open a saved capture?',
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                return
            self.stop_capture()
            
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Capture File", "",
                                                 "Capture Files (*.json);;All Files (*)")
        if file_name:
            try:
                with open(file_name, 'r') as f:
                    data = json.load(f)
                    self.packets = data['packets']
                    self.current_file = file_name
                    
                    # Update packet table
                    self.packet_table.setRowCount(0)
                    for packet in self.packets:
                        row = self.packet_table.rowCount()
                        self.packet_table.insertRow(row)
                        for col, key in enumerate(['timestamp', 'source', 'destination', 'protocol', 'length', 'type', 'details']):
                            item = QTableWidgetItem(str(packet[key]))
                            if key == 'type' and packet[key] in self.protocol_colors:
                                item.setBackground(self.protocol_colors[packet[key]])
                            self.packet_table.setItem(row, col, item)
                            
                    # Update statistics
                    self.update_capture_info()
                    self.statusBar.showMessage(f"Opened capture file: {file_name}")
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open capture file: {str(e)}")
                
    def save_capture(self):
        if not self.packets:
            QMessageBox.warning(self, "Warning", "No packets to save.")
            return
            
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Capture File", "",
                                                 "Capture Files (*.json);;All Files (*)")
        if file_name:
            try:
                data = {
                    'packets': self.packets,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'total_packets': len(self.packets),
                    'total_bytes': sum(p['length'] for p in self.packets)
                }
                
                with open(file_name, 'w') as f:
                    json.dump(data, f, indent=2)
                    
                self.current_file = file_name
                self.statusBar.showMessage(f"Saved capture to: {file_name}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save capture file: {str(e)}")
                
    def clear_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            reply = QMessageBox.question(self, 'Clear Capture',
                                       'A capture is currently running. Do you want to stop it and clear the capture?',
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                return
            self.stop_capture()
            
        self.packets = []
        self.packet_table.setRowCount(0)
        self.alerts_table.setRowCount(0)
        self.current_file = None
        
        # Reset statistics
        self.packet_count_label.setText("0")
        self.byte_count_label.setText("0")
        self.duration_label.setText("00:00:00")
        
        # Clear graphs
        self.protocol_canvas.figure.clear()
        self.protocol_canvas.draw()
        self.traffic_canvas.figure.clear()
        self.traffic_canvas.draw()
        self.graph_canvas.figure.clear()
        self.graph_canvas.draw()
        
        self.statusBar.showMessage("Capture cleared")
        
    def show_statistics(self):
        # Switch to statistics tab
        self.tab_widget.setCurrentWidget(self.stats_widget)
        
        # Update statistics if we have packets
        if self.packets:
            # Update protocol statistics
            protocol_counts = defaultdict(int)
            for packet in self.packets:
                protocol_counts[packet['protocol']] += 1
            self.update_statistics(dict(protocol_counts))
            
            # Update traffic statistics
            traffic_data = {
                'timestamps': list(range(len(self.packets))),
                'packet_counts': list(range(1, len(self.packets) + 1)),
                'byte_counts': [p['length'] for p in self.packets]
            }
            self.update_traffic(traffic_data)
            
    def export_pcap(self):
        if not self.packets:
            QMessageBox.warning(self, "Warning", "No packets to export.")
            return
            
        file_name, _ = QFileDialog.getSaveFileName(self, "Export as PCAP", "",
                                                 "PCAP Files (*.pcap);;All Files (*)")
        if file_name:
            try:
                # Create a list of scapy packets
                scapy_packets = []
                for packet in self.packets:
                    # Convert raw packet data back to scapy packet
                    raw_data = packet['raw']
                    scapy_packet = scapy.Ether(raw_data)
                    scapy_packets.append(scapy_packet)
                
                # Write packets to PCAP file
                wrpcap(file_name, scapy_packets)
                self.statusBar.showMessage(f"Exported capture to PCAP: {file_name}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export PCAP file: {str(e)}")
                
    def export_csv(self):
        if not self.packets:
            QMessageBox.warning(self, "Warning", "No packets to export.")
            return
            
        file_name, _ = QFileDialog.getSaveFileName(self, "Export as CSV", "",
                                                 "CSV Files (*.csv);;All Files (*)")
        if file_name:
            try:
                with open(file_name, 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Type'])
                    # Write packet data
                    for packet in self.packets:
                        writer.writerow([
                            packet['timestamp'],
                            packet['source'],
                            packet['destination'],
                            packet['protocol'],
                            packet['length'],
                            packet['type']
                        ])
                self.statusBar.showMessage(f"Exported capture to CSV: {file_name}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export CSV file: {str(e)}")
                
    def closeEvent(self, event):
        self.stop_capture()
        event.accept()

    def update_ui(self):

        current_tab = self.tab_widget.currentWidget()
        if current_tab == self.stats_widget:
            self.update_statistics(self.stats)
        elif current_tab == self.graph_widget:
            self.analyze_traffic()
            
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Netxtrack()
    window.show()
    sys.exit(app.exec_()) 
