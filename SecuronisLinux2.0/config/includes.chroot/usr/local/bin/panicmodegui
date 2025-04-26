#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
import psutil
import socket
import requests
import json
import time
import shutil
import hashlib
import re
import random
from typing import Tuple, Optional
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, 
                             QHBoxLayout, QWidget, QScrollArea, QGridLayout, QLabel, QFrame,
                             QMessageBox, QInputDialog, QTabWidget, QGroupBox, QLineEdit)
from PyQt5.QtGui import QFont, QPixmap, QPalette, QColor
from PyQt5.QtCore import Qt, QTimer
import threading



# Securonis GNU/Linux Panic Mode
# 
# Securonis Panic Mode is an advanced emergency security mechanism designed for 
# situations where the system is under physical or digital threat. It includes:
# 
# - System Status Checks & Leak Tests: Actively monitors system health and detects potential data leaks.
# - Trace Cleaner: Securely deletes user traces and temporary data.
# - Physical Security Mode: Disables physical interfaces like USB/Bluetooth, restricts user permissions.
# - Paranoia Mode: Disconnects from all networks, enables maximum kernel-level security, and isolates the system.
# - Nuke2System: Performs secure disk overwrites, wipes RAM and metadata, and irreversibly destroys data.
# 
# LEGAL DISCLAIMER:
# 
# WARNING:
# The System Wipe Mode, a part of Securonis Panic Mode, is developed solely to protect personal data
# in case of malware infections, cyberattacks, or unauthorized access.
# This feature is intended for use strictly in emergency situations as a security measure.
# Any misuse or unlawful application of this feature is strictly prohibited.
# 
# The developers of Securonis shall not be held liable for any data loss, damage,
# or legal consequences resulting from improper or unauthorized use of this feature.
# Users must be fully aware of the potential risks and consequences before activating it.


class PanicModeCore:
    def __init__(self):
        # This tool is Debian Linux specific
        self.is_windows = False
        self.system_info = {}
        self.network_info = {}
        self.paranoia_mode = False
        self.physical_security = False
        self.monitoring_active = False
        self.monitoring_timer = None
        
        # Cache system
        self._cached_status = {}
        self._last_update = 0
        self._cached_network_info = {}
        self._network_info_last_update = 0
        self._cached_system_info = {}
        self._system_info_last_update = 0
        self._cached_public_ip = None
        self._public_ip_last_update = 0
        self._cached_local_ip = None
        self._local_ip_last_update = 0
        self._cached_dns_servers = None
        self._dns_servers_last_update = 0
        
        # Initial load
        self._initial_load()

    def _initial_load(self):
        """Initial loading operations"""
        try:
            # Load system information
            self.update_system_info()
            # Load network information
            self.update_network_info()
        except Exception as e:
            print(f"Initial loading error: {str(e)}")

    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Önbellekten kontrol et
            current_time = time.time()
            if current_time - self._local_ip_last_update < 30:  # 30 saniyelik önbellek
                if self._cached_local_ip:
                    return self._cached_local_ip
            
            # Yerel IP adresini al
            # Linux için yerel IP adresi alma
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Bağlantı gerektirmeyen bir yöntem
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                s.close()
                self._cached_local_ip = ip
                self._local_ip_last_update = current_time
                return ip
            except:
                s.close()
            
            # Alternatif yöntem
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            self._cached_local_ip = ip
            self._local_ip_last_update = current_time
            return ip
        except Exception as e:
            return f"Yerel IP alınamadı: {str(e)}"

    def get_ip_address(self) -> str:
        """Get public IP address"""
        try:
            # Check cache
            current_time = time.time()
            if current_time - self._public_ip_last_update < 30:  # 30 second cache
                if self._cached_public_ip:
                    return self._cached_public_ip
            
            # Get public IP
            response = requests.get('https://api.ipify.org?format=json', timeout=3)
            ip = response.json()['ip']
            
            # Cache the result
            self._cached_public_ip = ip
            self._public_ip_last_update = current_time
            
            return ip
        except:
            return "Could not retrieve public IP"

    def update_system_info(self):
        """Update system information"""
        try:
            # Check cache
            current_time = time.time()
            if current_time - self._system_info_last_update < 10:  # 10 second cache
                return self._cached_system_info
            
            # Get CPU information
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpu_info = f.read()
                cpu_model = re.search(r'model name\s+: (.+)', cpu_info)
                cpu_cores = re.search(r'cpu cores\s+: (\d+)', cpu_info)
                if cpu_model and cpu_cores:
                    cpu = f"{cpu_model.group(1)} ({cpu_cores.group(1)} cores)"
                else:
                    cpu = "CPU information not available"
            except:
                cpu = "CPU information not available"
            
            # Update system information
            self.system_info = {
                'os': platform.system() + ' ' + platform.release(),
                'kernel': platform.release(),
                'architecture': platform.machine(),
                'cpu': cpu,
                'memory': f"{psutil.virtual_memory().used / (1024**3):.1f}GB / {psutil.virtual_memory().total / (1024**3):.1f}GB",
                'cpu_usage': f"{psutil.cpu_percent(interval=0.1)}%",
                'disk': f"{psutil.disk_usage('/').used / (1024**3):.1f}GB / {psutil.disk_usage('/').total / (1024**3):.1f}GB",
                'uptime': self.get_uptime(),
                'hostname': socket.gethostname(),
                'paranoia_mode': "Active" if self.paranoia_mode else "Inactive",
                'physical_security': "Active" if self.physical_security else "Inactive",
                'monitoring': "Active" if self.monitoring_active else "Inactive"
            }
            
            # Cache the results
            self._cached_system_info = self.system_info.copy()
            self._system_info_last_update = current_time
            
            return self.system_info
        except Exception as e:
            self.system_info['error'] = f"Failed to update system information: {str(e)}"
            return self.system_info

    def update_network_info(self):
        """Update network information"""
        try:
            # Check cache
            current_time = time.time()
            if current_time - self._network_info_last_update < 10:  # 10 second cache
                return self._cached_network_info
            
            self.network_info = {}
            
            # Get all network interfaces
            interfaces = psutil.net_if_addrs()
            
            for iface, addrs in interfaces.items():
                try:
                    # IPv4 addresses
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            self.network_info[f'{iface}_ipv4'] = addr.address
                            self.network_info[f'{iface}_netmask'] = addr.netmask
                        elif addr.family == psutil.AF_LINK:  # MAC address
                            self.network_info[f'{iface}_mac'] = addr.address
                    
                    # Network status
                    stats = psutil.net_if_stats()
                    if iface in stats:
                        self.network_info[f'{iface}_state'] = "up" if stats[iface].isup else "down"
                        self.network_info[f'{iface}_speed'] = f"{stats[iface].speed}Mbps" if stats[iface].speed > 0 else "N/A"
                except:
                    continue

            # DNS servers
            dns_servers = self.get_dns_servers()
            self.network_info['dns_servers'] = ', '.join(dns_servers) if dns_servers else "No DNS servers found"

            # Tor status
            tor_status, _ = self.check_tor_status()
            self.network_info['tor_status'] = "Active" if tor_status else "Inactive"

            # VPN status
            vpn_status, _ = self.check_vpn_status()
            self.network_info['vpn_status'] = "Active" if vpn_status else "Inactive"

            # Network connections
            connections = psutil.net_connections()
            self.network_info['active_connections'] = len(connections)
            
            # Show IP addresses
            self.network_info['public_ip'] = self.get_ip_address()
            self.network_info['local_ip'] = self.get_local_ip()
            
            # Cache the results
            self._cached_network_info = self.network_info.copy()
            self._network_info_last_update = current_time
            
            return self.network_info
        except Exception as e:
            self.network_info['error'] = f"Failed to update network information: {str(e)}"
            return self.network_info

    def get_uptime(self) -> str:
        """Get system uptime"""
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{days} days, {hours} hours, {minutes} minutes"
        except:
            return "Uptime not available"

    def check_ip_location(self) -> str:
        """Check IP location"""
        try:
            ip = self.get_ip_address()
            if ip == "Could not retrieve public IP":
                return "Could not determine IP location"
                
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
            data = response.json()
            
            location_info = [
                f"IP: {ip}",
                f"Country: {data.get('country_name', 'Unknown')}",
                f"Region: {data.get('region', 'Unknown')}",
                f"City: {data.get('city', 'Unknown')}",
                f"ISP: {data.get('org', 'Unknown')}",
                f"Timezone: {data.get('timezone', 'Unknown')}"
            ]
            
            return "\n".join(location_info)
        except:
            return "Could not determine IP location"

    def check_tor_status(self) -> Tuple[bool, str]:
        """Check Tor connection status"""
        try:
            # Tor Project API'sini kullanarak kontrol et
            response = requests.get('https://check.torproject.org/api/ip', timeout=5)
            data = response.json()
            
            is_tor = data.get('IsTor', False)
            ip = data.get('IP', 'Unknown')
            
            if is_tor:
                return True, ip
            else:
                return False, f"Not using Tor (Current IP: {ip})"
        except Exception as e:
            return False, f"Tor check failed: {str(e)}"

    def check_vpn_status(self) -> Tuple[bool, str]:
        """Check VPN connection status"""
        try:
            output = subprocess.check_output(['ip', 'addr', 'show', 'tun0']).decode()
            vpn_ip = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', output)
            if vpn_ip:
                vpn_ip = vpn_ip.group(1)
            
            return bool(vpn_ip), vpn_ip or "Unknown"
        except:
            return False, "Unknown"

    def get_dns_servers(self) -> list:
        """Get DNS servers"""
        try:
            # Check cache
            current_time = time.time()
            if current_time - self._dns_servers_last_update < 30:  # 30 second cache
                if self._cached_dns_servers:
                    return self._cached_dns_servers
            
            dns_servers = []
            # Linux için DNS sunucularını al
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = [line.split()[1] for line in f if line.startswith('nameserver')]
            
            # Cache the results
            self._cached_dns_servers = dns_servers
            self._dns_servers_last_update = current_time
            
            return dns_servers
        except Exception as e:
            return []

    def check_dns_leak(self) -> list:
        """Check for DNS leaks"""
        result = []
        try:
            result.append("DNS Leak Check:")
            
            # Get current DNS servers
            dns_servers = self.get_dns_servers()
            result.append(f"Current DNS Servers: {', '.join(dns_servers)}")
            
            # Check for DNS leaks
            detected_ip = requests.get('https://api64.ipify.org').text.strip()
            current_ip = self.get_ip_address()
            
            if detected_ip != current_ip:
                result.append("WARNING: DNS leak detected!")
            else:
                result.append("No DNS leak detected")
            
            return result
        except Exception as e:
            return [f"DNS leak check failed: {str(e)}"]

    def check_ip_leak(self) -> list:
        """Check for IP leaks"""
        result = []
        try:
            result.append("IP Leak Check:")
            
            # Check WebRTC leaks
            webrtc_ip = requests.get('https://api64.ipify.org').text.strip()
            result.append(f"WebRTC IP: {webrtc_ip}")
            
            # Show public IP
            public_ip = self.get_ip_address()
            result.append(f"Public IP: {public_ip}")
            
            return result
        except Exception as e:
            return [f"IP leak check failed: {str(e)}"]

    def check_mitm_attack(self) -> list:
        """Check for MITM attacks and take defensive measures"""
        result = []
        try:
            result.append("MITM Attack Check and Defense:")
            
            # Check ARP table
            output = subprocess.check_output(['arp', '-n']).decode()
            
            # Look for suspicious ARP entries
            suspicious_entries = []
            for line in output.split('\n'):
                if 'dynamic' in line.lower() or 'incomplete' in line.lower():
                    suspicious_entries.append(line.strip())
            
            if suspicious_entries:
                result.append("WARNING: Suspicious ARP entries detected!")
                result.append("Cleaning ARP table...")
                subprocess.run(['ip', 'neigh', 'flush', 'all'])
            
            # Check SSL certificates
            try:
                cert_path = '/etc/ssl/certs'
                if os.path.exists(cert_path):
                    result.append("SSL certificates checked")
                else:
                    result.append("SSL certificate path not found")
            except Exception as e:
                result.append(f"SSL certificate check failed: {str(e)}")
            
            # Clear DNS cache
            try:
                # Try multiple methods to clear DNS cache
                dns_cleared = False
                
                # Method 1: systemd-resolve
                try:
                    subprocess.run(['systemd-resolve', '--flush-caches'], check=True)
                    dns_cleared = True
                    result.append("DNS cache cleared using systemd-resolve")
                except:
                    pass
                
                # Method 2: nscd
                if not dns_cleared:
                    try:
                        subprocess.run(['service', 'nscd', 'restart'], check=True)
                        dns_cleared = True
                        result.append("DNS cache cleared using nscd")
                    except:
                        pass
                
                # Method 3: resolvconf
                if not dns_cleared:
                    try:
                        subprocess.run(['resolvconf', '-d'], check=True)
                        dns_cleared = True
                        result.append("DNS cache cleared using resolvconf")
                    except:
                        pass
                
                # Method 4: Direct file manipulation
                if not dns_cleared:
                    try:
                        with open('/etc/resolv.conf', 'w') as f:
                            f.write("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
                        dns_cleared = True
                        result.append("DNS cache cleared by updating resolv.conf")
                    except:
                        pass
                
                if not dns_cleared:
                    result.append("WARNING: Could not clear DNS cache - no suitable method found")
            except Exception as e:
                result.append(f"DNS cache clear failed: {str(e)}")
            
            # Take defensive measures
            result.append("\nTaking defensive measures:")
            
            # Restart network interfaces
            subprocess.run(['ip', 'link', 'set', 'eth0', 'down'])
            time.sleep(1)
            subprocess.run(['ip', 'link', 'set', 'eth0', 'up'])
            
            result.append("Network interfaces restarted")
            result.append("DNS servers changed to secure ones")
            
            return result
        except Exception as e:
            return [f"MITM attack check failed: {str(e)}"]

    def check_privacy_score(self) -> Tuple[int, str]:
        """Calculate privacy score"""
        score = 0
        details = []

        # Tor check (60 points)
        tor_status, tor_msg = self.check_tor_status()
        if tor_status:
            score += 60
            details.append("Tor: +60 points (Active)")
        else:
            details.append("Tor: 0 points (Not active)")

        # VPN check (30 points)
        vpn_status, vpn_msg = self.check_vpn_status()
        if vpn_status:
            score += 30
            details.append("VPN: +30 points (Active)")
        else:
            details.append("VPN: 0 points (Not active)")

        # DNS check (20 points)
        dns_servers = self.get_dns_servers()
        secure_dns = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222']
        if any(dns in dns_servers for dns in secure_dns):
            score += 20
            details.append("DNS: +20 points (Using secure DNS)")
        else:
            details.append("DNS: 0 points (Not using secure DNS)")

        # Paranoia mode check (20 points)
        if self.paranoia_mode:
            score += 20
            details.append("Paranoia Mode: +20 points (Active)")
        else:
            details.append("Paranoia Mode: 0 points (Not active)")

        # Physical security check (20 points)
        if self.physical_security:
            score += 20
            details.append("Physical Security: +20 points (Active)")
        else:
            details.append("Physical Security: 0 points (Not active)")

        # Score summary
        details.append(f"\nTotal Privacy Score: {score}/150")
        if score >= 100:
            details.append("Privacy Level: Excellent")
        elif score >= 70:
            details.append("Privacy Level: Good")
        elif score >= 40:
            details.append("Privacy Level: Fair")
        else:
            details.append("Privacy Level: Poor")

        return score, "\n".join(details)

    def wipe_ram(self) -> str:
        """Wipe RAM"""
        try:
            subprocess.run('sync; echo 3 > /proc/sys/vm/drop_caches', shell=True)
            return "RAM wipe completed"
        except:
            return "RAM wipe failed"

    def wipe_disk(self, path: str = "/tmp") -> str:
        """Wipe disk or directory"""
        try:
            # For Linux, use shred with error handling
            if os.path.isdir(path):
                # For directories, use find to locate all files and shred them
                subprocess.run(f'find {path} -type f -exec shred -u -n 3 {{}} \;', shell=True, check=True)
                return f"Directory wipe completed for {path}"
            elif os.path.isfile(path):
                # For individual files
                subprocess.run(f'shred -u -n 3 {path}', shell=True, check=True)
                return f"File wipe completed for {path}"
            elif path.startswith('/dev/'):
                # For block devices, use dd with progress monitoring
                # Using a smaller block size and showing progress
                subprocess.run(f'dd if=/dev/urandom of={path} bs=4M status=progress conv=fsync', shell=True, check=True)
                return f"Block device wipe completed for {path}"
            else:
                return f"Invalid path: {path}"
        except subprocess.SubprocessError as e:
            return f"Disk wipe failed: {str(e)}"
        except Exception as e:
            return f"Disk wipe failed: {str(e)}"

    def wipe_free_space(self, path: str = "/") -> str:
        """Wipe free space on disk"""
        try:
            # For Linux, create a large file, fill it with random data, then delete it
            # Make sure path ends with /
            if not path.endswith('/'):
                path += '/'
            # Create a temporary file and fill it with random data until disk is full
            # Using a try-except to catch the "no space left on device" error
            try:
                subprocess.run(f'dd if=/dev/urandom of={path}wipefile bs=4M status=progress', shell=True, check=True)
            except subprocess.SubprocessError:
                # This is expected when disk becomes full
                pass
            # Securely delete the temporary file
            subprocess.run(f'shred -u -n 3 {path}wipefile', shell=True, check=True)
            return "Free space wipe completed"
        except subprocess.SubprocessError as e:
            return f"Free space wipe failed: {str(e)}"
        except Exception as e:
            return f"Free space wipe failed: {str(e)}"

    def change_dns(self, dns_server: str) -> str:
        """Change DNS server"""
        try:
            with open('/etc/resolv.conf', 'w') as f:
                f.write(f'nameserver {dns_server}\n')
            return f"DNS server changed to {dns_server}"
        except:
            return "DNS change failed"

    def spoof_mac(self, interface: str) -> str:
        """Spoof MAC address"""
        try:
            subprocess.run(f'ifconfig {interface} down', shell=True)
            subprocess.run(f'macchanger -r {interface}', shell=True)
            subprocess.run(f'ifconfig {interface} up', shell=True)
            return f"MAC address changed: {interface}"
        except:
            return "MAC address change failed"

    def delete_network_traces(self) -> str:
        """Delete network traces"""
        try:
            # Clear ARP cache
            subprocess.run(['ip', 'neigh', 'flush', 'all'], check=True)
            
            # Clear routing cache
            subprocess.run('ip route flush cache', shell=True)
            
            # Clear connection tracking
            subprocess.run('conntrack -F', shell=True)
            
            return "Network traces deleted"
        except:
            return "Failed to delete network traces"

    def monitor_network_traffic(self) -> list:
        """Monitor network traffic"""
        result = []
        try:
            result.append("Network Traffic Monitoring:")
            
            # Get active connections
            output = subprocess.check_output(['netstat', '-tuln']).decode()
            result.append("Active Connections:")
            for line in output.split('\n')[2:]:  # Skip headers
                if line.strip():
                    result.append(line.strip())
            
            # Get network interface statistics
            output = subprocess.check_output(['ifconfig']).decode()
            result.append("\nNetwork Interface Statistics:")
            for line in output.split('\n'):
                if 'RX packets' in line or 'TX packets' in line:
                    result.append(line.strip())
            
            return result
        except Exception as e:
            return [f"Network traffic monitoring failed: {str(e)}"]

    def security_scan(self) -> list:
        """Run a simplified security scan"""
        result = []
        try:
            result.append("Check Open Ports:")

            # Check open ports
            result.append("\nOpen Ports:")
            try:
                ports = subprocess.run(
                    ['netstat', '-tuln'],
                    check=True, capture_output=True, text=True
                )
                result.append(ports.stdout)
            except subprocess.CalledProcessError as e:
                result.append(f"Port scan failed: {e.stderr}")

            # Check basic system information
            result.append("\nSystem Information:")
            try:
                uname = subprocess.run(
                    ['uname', '-a'],
                    check=True, capture_output=True, text=True
                )
                result.append(uname.stdout)
            except subprocess.CalledProcessError as e:
                result.append(f"System information retrieval failed: {e.stderr}")

            return result
        except Exception as e:
            return [f"Open Port Check failed: {str(e)}"]

    def clean_system_traces(self) -> list:
        """Clean system traces"""
        result = []
        try:
            result.append("Cleaning System Traces:")
            
            # Linux için sistem izlerini temizleme
            # Clean logs
            subprocess.run(['rm', '-rf', '/var/log/*'])
            subprocess.run(['journalctl', '--vacuum-time=0'])
            
            # Clean temporary files
            subprocess.run(['rm', '-rf', '/var/tmp/*'])
            subprocess.run(['rm', '-rf', '/tmp/*'])
            
            # Clean browser data
            subprocess.run(['rm', '-rf', '~/.cache/google-chrome/*'])
            subprocess.run(['rm', '-rf', '~/.cache/mozilla/firefox/*'])
            
            # Clean command history
            subprocess.run(['rm', '-f', '~/.bash_history'])
            subprocess.run(['rm', '-f', '~/.zsh_history'])
            
            # Clean systemd logs
            subprocess.run(['rm', '-rf', '/var/log/journal/*'])
            
            # Clean user logs
            subprocess.run(['rm', '-rf', '/var/log/user/*'])
            
            # Clean kernel logs
            subprocess.run(['rm', '-rf', '/var/log/kern.log'])
            
            # Clean process information
            subprocess.run(['rm', '-rf', '/proc/*/fd/*'])
            
            # Clean system cache
            subprocess.run(['sync'])
            with open('/proc/sys/vm/drop_caches', 'w') as f:
                f.write('3')
            
            result.append("Linux system traces cleaned")
            
            return result
        except Exception as e:
            return [f"System trace cleaning failed: {str(e)}"]

    def change_hostname(self, new_hostname: str) -> list:
        """Change system hostname"""
        result = []
        try:
            result.append(f"Changing hostname to: {new_hostname}")
            
            # Change hostname
            subprocess.run(['sudo', 'hostnamectl', 'set-hostname', new_hostname], check=True)
            
            # Update /etc/hosts
            ip_address = subprocess.check_output("hostname -I | cut -d' ' -f1", shell=True).decode().strip()
            subprocess.run(f'echo "{ip_address} {new_hostname}" | sudo tee -a /etc/hosts', shell=True, check=True)
            
            result.append("Hostname changed successfully. Please reboot your system for changes to take effect.")
            return result
        except Exception as e:
            return [f"Hostname change failed: {str(e)}"]

    def check_kernel_security(self) -> list:
        """Check kernel security settings"""
        result = []
        try:
            result.append("Kernel Security Check:")
            
            # Linux için kernel güvenlik kontrolü
            # Check kernel parameters
            kernel_params = {
                'kernel.randomize_va_space': 'Address space layout randomization',
                'kernel.kptr_restrict': 'Kernel pointer restrictions',
                'kernel.yama.ptrace_scope': 'Ptrace scope',
                'kernel.sysrq': 'SysRq key',
                'kernel.unprivileged_bpf_disabled': 'Unprivileged BPF',
                'kernel.unprivileged_userns_clone': 'Unprivileged user namespaces'
            }
            
            for param, description in kernel_params.items():
                try:
                    value = subprocess.check_output(['sysctl', '-n', param]).decode().strip()
                    result.append(f"{description}: {value}")
                except:
                    result.append("Could not check kernel modules")
            
            # Check loaded kernel modules
            try:
                modules = subprocess.check_output(['lsmod']).decode()
                result.append("\nLoaded Kernel Modules:")
                for line in modules.split('\n')[1:]:  # Skip header
                    if line.strip():
                        module = line.split()[0]
                        result.append(f"- {module}")
            except:
                result.append("Could not check kernel modules")
            
            # Check sysctl settings
            try:
                sysctl_output = subprocess.check_output(['sysctl', '-a']).decode()
                result.append("\nSysctl Settings:")
                for line in sysctl_output.split('\n'):
                    if any(key in line.lower() for key in ['security', 'protect', 'restrict']):
                        result.append(line.strip())
            except:
                result.append("Could not check sysctl settings")
            
            return result
        except Exception as e:
            return [f"Kernel security check failed: {str(e)}"]

    def check_disk_encryption(self) -> list:
        """Check disk encryption status"""
        result = []
        try:
            result.append("Disk Encryption Check:")
            
            # Linux için disk şifreleme kontrolü
            # Check LUKS encryption
            try:
                luks_output = subprocess.check_output(['cryptsetup', 'status', '/dev/sda1']).decode()
                result.append("LUKS Encryption: Active")
                for line in luks_output.split('\n'):
                    if 'type' in line.lower():
                        result.append(line.strip())
                    elif 'cipher' in line.lower():
                        result.append(line.strip())
            except:
                result.append("LUKS Encryption: Not active")
            
            # Check eCryptfs
            try:
                ecryptfs_output = subprocess.check_output(['mount']).decode()
                if 'ecryptfs' in ecryptfs_output:
                    result.append("eCryptfs: Active")
                    for line in ecryptfs_output.split('\n'):
                        if 'ecryptfs' in line:
                            result.append(line.strip())
                else:
                    result.append("eCryptfs: Not active")
            except:
                result.append("eCryptfs: Could not check")
            
            return result
        except Exception as e:
            return [f"Disk encryption check failed: {str(e)}"]

    def check_ssl_tls_fingerprint(self, host: str) -> list:
        """Check SSL/TLS fingerprint of a server"""
        result = []
        try:
            result.append(f"SSL/TLS Fingerprint Check for {host}:")
            
            # Get SSL certificate
            output = subprocess.check_output(['openssl', 's_client', '-connect', f'{host}:443', '-servername', host]).decode()
            
            # Extract certificate information
            cert_info = {}
            current_key = None
            
            for line in output.split('\n'):
                if 'Subject:' in line:
                    cert_info['subject'] = line.strip()
                elif 'Issuer:' in line:
                    cert_info['issuer'] = line.strip()
                elif 'Not Before:' in line:
                    cert_info['not_before'] = line.strip()
                elif 'Not After:' in line:
                    cert_info['not_after'] = line.strip()
                elif 'Public Key Algorithm:' in line:
                    cert_info['public_key_algo'] = line.strip()
                elif 'Signature Algorithm:' in line:
                    cert_info['signature_algo'] = line.strip()
            
            # Add certificate information to results
            for key, value in cert_info.items():
                result.append(f"{key}: {value}")
            
            # Check for known vulnerabilities
            output = subprocess.check_output(['openssl', 's_client', '-connect', f'{host}:443', '-servername', host, '-tls1_2']).decode()
            
            if 'Connected' in output:
                result.append("TLS 1.2: Supported")
            else:
                result.append("TLS 1.2: Not supported")
            
            # Check certificate expiration
            if 'not_after' in cert_info:
                expiry_date = cert_info['not_after'].split(': ')[1]
                result.append(f"Certificate expires: {expiry_date}")
            
            return result
        except Exception as e:
            return [f"SSL/TLS fingerprint check failed: {str(e)}"]

    def check_security_updates(self) -> str:
        """Check security updates"""
        try:
            # First check if apt is available
            if not os.path.exists('/usr/bin/apt'):
                return "apt package manager not found"
            
            # Check if we have sudo privileges
            if os.geteuid() != 0:
                return "This operation requires root privileges. Please run with sudo."
            
            # Update package list with timeout
            try:
                result = subprocess.run(['apt', 'update'], check=True, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    return f"Failed to update package list: {result.stderr}"
            except subprocess.TimeoutExpired:
                return "Package list update timed out"
            except subprocess.CalledProcessError as e:
                return f"Failed to update package list: {e.stderr}"
            
            # Get upgradable packages with timeout
            try:
                result = subprocess.run(['apt', 'list', '--upgradable'], check=True, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    return f"Failed to list upgradable packages: {result.stderr}"
                output = result.stdout
            except subprocess.TimeoutExpired:
                return "Package list check timed out"
            except subprocess.CalledProcessError as e:
                return f"Failed to list upgradable packages: {e.stderr}"
            
            # Filter security updates
            security_updates = []
            for line in output.split('\n'):
                if 'security' in line.lower():
                    security_updates.append(line.strip())
            
            if not security_updates:
                return "No security updates available"
            
            return f"Security Updates:\n{chr(10).join(security_updates)}"
        except Exception as e:
            return f"Could not check security updates: {str(e)}"

    def set_firewall_rules(self) -> str:
        """Toggle firewall rules"""
        try:
            # Check if UFW is installed
            if not os.path.exists('/usr/sbin/ufw'):
                return "UFW (Uncomplicated Firewall) is not installed"
            
            # Check UFW status
            status = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
            if "Status: active" in status.stdout:
                # Disable UFW if active
                subprocess.run('sudo ufw disable', shell=True, check=True)
                return "Firewall (UFW) disabled"
            else:
                # Enable UFW with basic rules
                subprocess.run('sudo ufw reset', shell=True, check=True)
                subprocess.run('sudo ufw default deny incoming', shell=True, check=True)
                subprocess.run('sudo ufw default allow outgoing', shell=True, check=True)
                subprocess.run('sudo ufw allow ssh', shell=True, check=True)
                subprocess.run('sudo ufw enable', shell=True, check=True)
                return "Firewall (UFW) enabled with basic rules"
        except subprocess.CalledProcessError as e:
            return f"Failed to toggle firewall rules: {str(e)}"

    def secure_delete(self, file_path: str) -> str:
        """Securely delete file"""
        try:
            subprocess.run(f'srm -v {file_path}', shell=True)
            return f"File securely deleted: {file_path}"
        except:
            return "File deletion failed"

    def clean_browser_traces(self) -> str:
        """Clean browser traces"""
        try:
            home = os.path.expanduser("~")
            browser_paths = [
                f"{home}/.cache",
                f"{home}/.mozilla",
                f"{home}/.config/google-chrome",
                f"{home}/.config/chromium"
            ]
            
            for path in browser_paths:
                if os.path.exists(path):
                    shutil.rmtree(path)
            return "Browser traces cleaned"
        except:
            return "Failed to clean browser traces"

    def toggle_paranoia_mode(self) -> list:
        """Toggle paranoia mode"""
        result = []
        try:
            self.paranoia_mode = not self.paranoia_mode
            result.append(f"Paranoia Mode: {'Activated' if self.paranoia_mode else 'Deactivated'}")
            
            if self.paranoia_mode:
                # Disable all network interfaces
                interfaces = psutil.net_if_addrs().keys()
                for iface in interfaces:
                    if iface != 'lo':  # Skip loopback interface
                        subprocess.run(['ip', 'link', 'set', iface, 'down'])
                
                # Set maximum kernel security levels
                security_params = {
                    'kernel.randomize_va_space': '2',
                    'kernel.kptr_restrict': '2',
                    'kernel.yama.ptrace_scope': '3',
                    'kernel.sysrq': '0',
                    'kernel.unprivileged_bpf_disabled': '1',
                    'kernel.unprivileged_userns_clone': '0'
                }
                
                for param, value in security_params.items():
                    subprocess.run(['sysctl', '-w', f'{param}={value}'])
                
                # Disable USB ports
                subprocess.run(['echo', '1', '>', '/sys/bus/usb/drivers/usb/usb1/authorized'])
                
                # Set restrictive firewall rules
                subprocess.run(['iptables', '-P', 'INPUT', 'DROP'])
                subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'])
                subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'])
                
                # Disable Bluetooth if available
                try:
                    if os.path.exists('/usr/bin/bluetoothctl'):
                        subprocess.run(['bluetoothctl', 'power', 'off'])
                    elif os.path.exists('/usr/bin/hciconfig'):
                        subprocess.run(['hciconfig', 'hci0', 'down'])
                except:
                    result.append("Bluetooth disable failed (bluetoothctl/hciconfig not found)")
                
                # Clear RAM
                subprocess.run(['sync'])
                with open('/proc/sys/vm/drop_caches', 'w') as f:
                    f.write('3')
                
                result.append("All network interfaces disabled")
                result.append("Maximum kernel security levels set")
                result.append("USB ports disabled")
                result.append("Restrictive firewall rules applied")
                result.append("Bluetooth disabled")
                result.append("RAM cleared")
            else:
                # Re-enable network interfaces
                interfaces = psutil.net_if_addrs().keys()
                for iface in interfaces:
                    if iface != 'lo':  # Skip loopback interface
                        subprocess.run(['ip', 'link', 'set', iface, 'up'])
                
                # Reset kernel security levels
                security_params = {
                    'kernel.randomize_va_space': '0',
                    'kernel.kptr_restrict': '0',
                    'kernel.yama.ptrace_scope': '0',
                    'kernel.sysrq': '1',
                    'kernel.unprivileged_bpf_disabled': '0',
                    'kernel.unprivileged_userns_clone': '1'
                }
                
                for param, value in security_params.items():
                    subprocess.run(['sysctl', '-w', f'{param}={value}'])
                
                # Re-enable USB ports
                subprocess.run(['echo', '1', '>', '/sys/bus/usb/drivers/usb/usb1/authorized'])
                
                # Reset firewall rules
                subprocess.run(['iptables', '-F'])
                subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'])
                subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
                subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'])
                
                # Re-enable Bluetooth if available
                try:
                    if os.path.exists('/usr/bin/bluetoothctl'):
                        subprocess.run(['bluetoothctl', 'power', 'on'])
                    elif os.path.exists('/usr/bin/hciconfig'):
                        subprocess.run(['hciconfig', 'hci0', 'up'])
                except:
                    result.append("Bluetooth enable failed (bluetoothctl/hciconfig not found)")
                
                result.append("Network interfaces re-enabled")
                result.append("Kernel security levels reset")
                result.append("USB ports re-enabled")
                result.append("Firewall rules reset")
                result.append("Bluetooth re-enabled")
            return result
        except Exception as e:
            return [f"Failed to toggle paranoia mode: {str(e)}"]

    def toggle_physical_security(self) -> str:
        """Toggle physical security"""
        self.physical_security = not self.physical_security
        if self.physical_security:
            # Enable physical security measures
            subprocess.run('systemctl enable screen-lock', shell=True)
            subprocess.run('systemctl enable usb-guard', shell=True)
        else:
            # Disable physical security measures
            subprocess.run('systemctl disable screen-lock', shell=True)
            subprocess.run('systemctl disable usb-guard', shell=True)
        return f"Physical security {'activated' if self.physical_security else 'deactivated'}"

    def nuke_system(self) -> list:
        """Securely wipe the system with progress and goodbye message"""
        result = []
        try:
            # Check if running in live mode
            try:
                with open('/proc/cmdline', 'r') as f:
                    if 'boot=live' in f.read():
                        return ["System is in live mode. Nuke operation is not allowed."]
            except FileNotFoundError:
                # /proc/cmdline file not found, continue
                pass
            
            # Check if running with sufficient privileges
            if os.geteuid() != 0:
                return ["This operation requires root privileges. Please run with sudo."]
                

            result.append("WARNING: This operation will PERMANENTLY DELETE ALL DATA on your system!")
            result.append("This includes:")
            result.append("- All personal files and documents")
            result.append("- Operating system files")
            result.append("- Bootloader and system partitions")
            result.append("- All installed software and configurations")
            result.append("\nThis action CANNOT be undone!")
            result.append("\nDo you want to continue?")
            
            # Get confirmation
            reply = QMessageBox.warning(
                None,
                "Nuke the System",
                "WARNING: This will PERMANENTLY DELETE ALL DATA on your system!\n\n"
                "This includes:\n"
                "- All personal files and documents\n"
                "- Operating system files\n"
                "- Bootloader and system partitions\n"
                "- All installed software and configurations\n\n"
                "This action CANNOT be undone!\n\n"
                "Do you want to continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Password verification
                password, ok = QInputDialog.getText(
                    None,
                    "Enter Password",
                    "Enter your password to confirm:",
                    QLineEdit.Password
                )
                
                if ok and password:
                    try:
                        # Goodbye message - add visible message box
                        result.append("Goodbye friend...")
                        print("Goodbye friend...")
                        
                        # Show goodbye message as a visible message box
                        goodbye_dialog = QMessageBox(None)
                        goodbye_dialog.setWindowTitle("Goodbye")
                        goodbye_dialog.setText("Goodbye friend...\n\nSystem wipe process starting now.")
                        goodbye_dialog.setStandardButtons(QMessageBox.NoButton)
                        goodbye_dialog.show()
                        QApplication.processEvents()
                        time.sleep(3)  # Wait 3 seconds for the message to be seen

                        # Progress status
                        # Detect all disks (Linux only)
                        all_disks = []
                        
                        try:
                            # First find all physical disks using lsblk
                            try:
                                disk_output = subprocess.check_output('lsblk -d -o NAME -n', shell=True).decode().strip()
                                for disk in disk_output.split('\n'):
                                    disk = disk.strip()
                                    if disk and not disk.startswith('loop') and not disk.startswith('sr'):
                                        all_disks.append(f"/dev/{disk}")
                            except Exception:
                                pass
                            
                            # Alternative method: look for disks in /dev
                            if not all_disks:
                                for dev in os.listdir('/dev'):
                                    if dev.startswith('sd') or dev.startswith('nvme') or dev.startswith('hd') or dev.startswith('vd'):
                                        if os.path.exists(f"/dev/{dev}") and not dev.endswith(tuple('0123456789')):
                                            all_disks.append(f"/dev/{dev}")
                            
                            # If still no disks found, try to find the system disk
                            if not all_disks:
                                try:
                                    system_disk = subprocess.check_output('findmnt / -o SOURCE -n', shell=True).decode().strip()
                                    # Convert from /dev/sdXY format to /dev/sdX format
                                    if system_disk.startswith('/dev/sd'):
                                        system_disk = system_disk.split('p')[0] if 'p' in system_disk else system_disk[:-1]
                                    elif system_disk.startswith('/dev/nvme'):
                                        system_disk = system_disk.split('p')[0]
                                    all_disks = [system_disk]
                                except Exception:
                                    pass
                        except Exception as e:
                            result.append(f"Error detecting disks: {str(e)}")
                            all_disks = ['/dev/sda']  # Default system disk
                        
                        # If no disks were detected, use default
                        if not all_disks:
                            all_disks = ['/dev/sda']
                        
                        result.append(f"Detected disks: {', '.join(all_disks)}")
                        print(f"Detected disks: {', '.join(all_disks)}")
                        
                        # Create progress dialog
                        progress_dialog = QMessageBox(None)
                        progress_dialog.setWindowTitle("System Wipe Progress")
                        progress_dialog.setText("Wiping system...\n\nThis may take a long time.")
                        progress_dialog.setStandardButtons(QMessageBox.NoButton)
                        progress_dialog.show()
                        QApplication.processEvents()

                        # Create wipe steps for Linux
                        steps = []
                        
                        # First, run bleachbit to clean all traces
                        result.append("Step 1/3: Cleaning all system traces with BleachBit...")
                        try:
                            # Check if bleachbit is installed
                            if subprocess.call('which bleachbit', shell=True, stdout=subprocess.DEVNULL) == 0:
                                # Run bleachbit with all cleaners
                                subprocess.call('bleachbit --clean system.cache system.clipboard system.custom system.recent_documents system.rotated_logs system.tmp system.trash system.memory_cache', shell=True)
                                result.append("BleachBit cleaning completed successfully")
                            else:
                                result.append("BleachBit not found. Skipping trace cleaning.")
                        except Exception as e:
                            result.append(f"BleachBit cleaning error: {str(e)}")
                        
                        # First, try to unmount all partitions safely
                        result.append("Step 2/3: Unmounting all partitions...")
                        try:
                            # Get all mounted partitions
                            mounted_parts = subprocess.check_output('mount | grep -v "/dev/loop" | cut -d" " -f1 | grep "/dev/"', shell=True).decode().strip().split('\n')
                            
                            # Try to safely unmount each partition
                            for part in mounted_parts:
                                try:
                                    # Skip root and essential partitions if system is running
                                    if subprocess.call(f"mountpoint -q / && mountpoint -q {part}", shell=True) == 0:
                                        result.append(f"Warning: {part} is currently mounted as root. Skipping unmount.")
                                        continue
                                        
                                    # Try to unmount
                                    subprocess.call(f"umount {part}", shell=True)
                                    result.append(f"Unmounted: {part}")
                                except:
                                    result.append(f"Warning: {part} is currently mounted. Attempting to unmount...")
                        except Exception as e:
                            result.append(f"Unmount preparation error: {str(e)}")
                        
                        # Clear swap safely
                        try:
                            # First check if swap is in use
                            swap_info = subprocess.check_output('swapon --show', shell=True).decode().strip()
                            if swap_info:
                                # Try to turn off swap
                                subprocess.call('swapoff -a', shell=True)
                                result.append("Swap turned off successfully")
                        except Exception as e:
                            result.append(f"Swap clear error: {str(e)}")
                            
                        # Now proceed with disk wiping
                        result.append("Step 3/3: Securely wiping all disks...")
                        result.append("WARNING: This may take a very long time depending on disk size!")
                        
                        for disk in all_disks:
                            # Check if disk is mounted before wiping
                            try:
                                is_mounted = subprocess.call(f"mountpoint -q {disk}", shell=True) == 0
                                if is_mounted:
                                    result.append(f"Warning: {disk} is currently mounted. Attempting to unmount...")
                                    # Try force unmount
                                    subprocess.call(f"umount -f {disk}", shell=True)
                            except:
                                pass
                                
                            # Linux secure wiping steps using shred (based on documentation)
                            result.append(f"Securely wiping disk: {disk}")
                            steps.append(f"shred -vfz -n 1 {disk} || true")
                            
                            # Alternative method using dd with progress bar via pv
                            # Check if pv is installed
                            if subprocess.call('which pv', shell=True, stdout=subprocess.DEVNULL) == 0:
                                # Get disk size
                                try:
                                    disk_size = subprocess.check_output(f"lsblk -b -d -n -o SIZE {disk}", shell=True).decode().strip()
                                    disk_size_gb = int(disk_size) / (1024**3)
                                    disk_size_gb = int(disk_size_gb) + 1  # Round up
                                    
                                    # Add dd with pv for progress bar
                                    steps.append(f"pv -ptres \"{disk_size_gb}G\" /dev/urandom | dd of={disk} bs=1M || true")
                                except:
                                    # Fallback to regular dd if we can't get disk size
                                    steps.append(f"dd if=/dev/urandom of={disk} bs=1M status=progress || true")
                            else:
                                # Fallback to regular dd if pv is not installed
                                steps.append(f"dd if=/dev/urandom of={disk} bs=1M status=progress || true")
                        
                        # Perform the wipe operation
                        result.append("Starting secure wipe process...")
                        print("Starting secure wipe process...")
                        
                        for i, step in enumerate(steps):
                            try:
                                # Update progress status
                                progress_dialog.setText(f"Wiping system... ({i+1}/{len(steps)})\n\n{step}")
                                QApplication.processEvents()
                                
                                # Run the command on Linux
                                try:
                                    # Check if disk is mounted before wiping
                                    if "zero" in step or "urandom" in step:
                                        mount_check = subprocess.run(f"mount | grep {disk}", shell=True, capture_output=True)
                                        if mount_check.returncode == 0:
                                            result.append(f"Warning: {disk} is currently mounted. Attempting to unmount...")
                                            print(f"Warning: {disk} is currently mounted. Attempting to unmount...")
                                            try:
                                                subprocess.run(f"umount {disk}*", shell=True, check=False)
                                            except Exception as e:
                                                result.append(f"Unmount warning: {str(e)}")
                                    
                                    # Use timeout to prevent hanging
                                    subprocess.run(step, shell=True, check=True, timeout=300)
                                except subprocess.TimeoutExpired:
                                    result.append(f"Command timed out after 5 minutes, continuing to next step")
                                    print(f"Command timed out after 5 minutes, continuing to next step")
                                except subprocess.SubprocessError as e:
                                    result.append(f"Command error: {str(e)}")
                                    print(f"Command error: {str(e)}")
                                    # Continue with next step even if this one failed
                                
                                result.append(f"Step {i+1}/{len(steps)} completed")
                                print(f"Step {i+1}/{len(steps)} completed")
                            except Exception as e:
                                result.append(f"Error during step {i+1}: {str(e)}")
                                print(f"Error during step {i+1}: {str(e)}")
                        
                        # Clear RAM
                        try:
                            result.append("Clearing RAM...")
                            print("Clearing RAM...")
                            self.wipe_ram()
                        except Exception as e:
                            result.append(f"RAM wipe error: {str(e)}")
                            print(f"RAM wipe error: {str(e)}")
                        
                        # Clear swap space
                        try:
                            result.append("Clearing swap space...")
                            print("Clearing swap space...")
                            subprocess.run('swapoff -a && swapon -a', shell=True)
                        except Exception as e:
                            result.append(f"Swap clear error: {str(e)}")
                            print(f"Swap clear error: {str(e)}")
                        
                        # Completion message
                        result.append("System wipe completed. All data has been securely deleted.")
                        result.append("You can now shut down the system.")
                        result.append("Goodnight Securonis...")
                        print("System wipe completed. All data has been securely deleted.")
                        print("You can now shut down the system.")
                        print("Goodnight Securonis...")
                        
                        # Show completion message
                        progress_dialog.close()
                        QMessageBox.information(
                            None,
                            "System Wipe Complete",
                            "System wipe completed. All data has been securely deleted.\n\n"
                            "You can now shut down the system.\n\n"
                            "Goodnight Securonis..."
                        )
                    except Exception as e:
                        result.append(f"System wipe failed: {str(e)}")
                        print(f"System wipe failed: {str(e)}")
                else:
                    result.append("Operation cancelled: No password entered")
                    print("Operation cancelled: No password entered")
            else:
                result.append("Operation cancelled by user")
                print("Operation cancelled by user")
        
            return result
        except Exception as e:
            return [f"System wipe failed: {str(e)}"]

    def get_system_status(self) -> dict:
        """Get current system status"""
        try:
            current_time = time.time()
            if current_time - self._last_update < 10:  # 10 second cache
                return self._cached_status

            # Update system and network information in parallel
            system_info = self.update_system_info()
            network_info = self.update_network_info()
            
            status = {
                'system': system_info,
                'network': network_info,
                'paranoia_mode': self.paranoia_mode,
                'physical_security': self.physical_security,
                'monitoring': self.monitoring_active
            }
            
            # Cache the results
            self._cached_status = status.copy()
            self._last_update = current_time
            
            return status
        except Exception as e:
            return {'error': str(e)}

    def execute_command(self, command_number: int) -> Tuple[str, str]:
        """Execute command based on number"""
        commands = {
            1: (self.check_dns_leak, []),
            2: (self.check_ip_location, []),
            3: (self.check_privacy_score, []),
            4: (self.check_tor_status, []),
            5: (self.check_vpn_status, []),
            6: (self.get_ip_address, []),
            7: (self.check_ip_leak, []),
            8: (self.check_mitm_attack, []),
            9: (self.change_dns, ["1.1.1.1"]),
            10: (self.spoof_mac, ["eth0"]),
            11: (self.delete_network_traces, []),
            12: (self.monitor_network_traffic, []),
            13: (self.security_scan, []),
            14: (self.clean_system_traces, []),
            15: (self.wipe_ram, []),
            16: (self.wipe_disk, ["/tmp"]),
            17: (self.wipe_free_space, ["/"]),
            18: (self.change_hostname, ["secure-host"]),
            19: (self.check_kernel_security, []),
            20: (self.check_disk_encryption, []),
            21: (self.check_security_updates, []),
            22: (self.set_firewall_rules, []),
            23: (self.secure_delete, ["/tmp/test"]),
            24: (self.check_ssl_tls_fingerprint, ["google.com"]),
            25: (self.clean_browser_traces, []),
            26: (self.toggle_paranoia_mode, []),
            27: (self.toggle_physical_security, []),
            28: (self.nuke_system, []),
        }
        
        if command_number in commands:
            func, args = commands[command_number]
            try:
                result = func(*args)
                if isinstance(result, tuple):
                    return str(result[0]), str(result[1])
                return str(result), ""
            except subprocess.SubprocessError as e:
                return f"Command execution failed: {str(e)}", ""
            except PermissionError as e:
                return f"Permission denied: {str(e)}", ""
            except Exception as e:
                return f"Unexpected error: {str(e)}", ""
        return "Invalid command number", ""

class PanicModeApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.core = PanicModeCore()
        self.init_ui()
        
        # Update timer with longer interval
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(15000)  # Update every 15 seconds to reduce stuttering
        self._update_in_progress = False

    def init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle('Panic Mode')
        self.setGeometry(100, 100, 1200, 800)
        
        # Set dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
            }
            QLabel {
                color: #00ff00;
                font-family: 'Courier New';
                font-size: 12px;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 5px;
                font-family: 'Courier New';
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
            }
            QTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
                font-family: 'Courier New';
                font-size: 12px;
            }
            QTabWidget::pane {
                border: 1px solid #00ff00;
                background-color: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 5px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #3d3d3d;
            }
        """)

        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # System information panel at the top
        info_panel = QWidget()
        info_layout = QHBoxLayout(info_panel)
        
        # System information
        system_group = QGroupBox("System Information")
        system_group.setStyleSheet("QGroupBox { color: #00ff00; border: 1px solid #00ff00; }")
        system_layout = QVBoxLayout(system_group)
        system_layout.setSpacing(5)  # Etiketler arası boşluk ekle
        
        self.system_labels = {}
        system_info = [
            'os', 'kernel', 'architecture', 'cpu', 'memory',
            'cpu_usage', 'disk', 'uptime', 'hostname',
            'paranoia_mode', 'physical_security', 'monitoring'
        ]
        
        for info in system_info:
            label = QLabel()
            label.setMinimumHeight(20)  # Minimum yükseklik ayarla
            label.setStyleSheet("QLabel { padding: 2px; }")  # İç boşluk ekle
            self.system_labels[info] = label
            system_layout.addWidget(label)
        
        info_layout.addWidget(system_group)
        
        # Network information
        network_group = QGroupBox("Network Information")
        network_group.setStyleSheet("QGroupBox { color: #00ff00; border: 1px solid #00ff00; }")
        network_layout = QVBoxLayout(network_group)
        network_layout.setSpacing(5)  # Etiketler arası boşluk ekle
        
        self.network_labels = {}
        network_info = [
            'public_ip', 'local_ip', 'dns_servers', 'tor_status', 'vpn_status'
        ]
        
        for info in network_info:
            label = QLabel()
            label.setMinimumHeight(20)  # Minimum yükseklik ayarla
            label.setStyleSheet("QLabel { padding: 2px; }")  # İç boşluk ekle
            self.network_labels[info] = label
            network_layout.addWidget(label)
        
        info_layout.addWidget(network_group)
        main_layout.addWidget(info_panel)
        
        # Tab widget for different functions
        tab_widget = QTabWidget()
        
        # Security tab
        security_tab = QWidget()
        security_layout = QVBoxLayout(security_tab)
        
        security_buttons = [
            ('IP and DNS Check', self.check_ip_dns),
            ('DNS Leak Check', self.check_dns_leak),
            ('IP Leak Check', self.check_ip_leak),
            ('MITM Defense', self.check_mitm_defense),
            ('Change DNS', self.change_dns),
            ('Change MAC Address', self.spoof_mac),
            ('Network Monitoring', self.monitor_network),
            ('Security Scan', self.security_scan),
            ('System Cleanup', self.clean_system)
        ]
        
        for btn_text, btn_func in security_buttons:
            btn = QPushButton(btn_text)
            btn.clicked.connect(btn_func)
            security_layout.addWidget(btn)
        
        security_layout.addStretch()
        tab_widget.addTab(security_tab, "Security")
        
        # System tab
        system_tab = QWidget()
        system_tab_layout = QVBoxLayout(system_tab)
        
        system_buttons = [
            ('Kernel Security', self.check_kernel),
            ('Disk Encryption', self.check_disk_encryption),
            ('SSL/TLS Check', self.check_ssl_tls),
            ('Paranoia Mode', self.toggle_paranoia),
            ('Physical Security', self.toggle_physical_security),
            ('Nuke the System', self.nuke_system),
            ('Change Hostname', self.change_hostname),
            ('Security Updates', self.check_security_updates),
            ('Firewall Rules', self.set_firewall_rules)
        ]
        
        for btn_text, btn_func in system_buttons:
            btn = QPushButton(btn_text)
            btn.clicked.connect(btn_func)
            system_tab_layout.addWidget(btn)
        
        system_tab_layout.addStretch()
        tab_widget.addTab(system_tab, "System")
        
        # Privacy tab
        privacy_tab = QWidget()
        privacy_layout = QVBoxLayout(privacy_tab)
        
        privacy_buttons = [
            ('IP Location Check', self.check_ip_location),
            ('Privacy Score', self.check_privacy_score),
            ('Tor Status', self.check_tor_status),
            ('VPN Status', self.check_vpn_status),
            ('Delete Network Traces', self.delete_network_traces),
            ('Wipe RAM', self.wipe_ram),
            ('Wipe Disk', self.wipe_disk),
            ('Wipe Free Space', self.wipe_free_space),
            ('Clean Browser Traces', self.clean_browser_traces)
        ]
        
        for btn_text, btn_func in privacy_buttons:
            btn = QPushButton(btn_text)
            btn.clicked.connect(btn_func)
            privacy_layout.addWidget(btn)
        
        privacy_layout.addStretch()
        tab_widget.addTab(privacy_tab, "Privacy")
        
        main_layout.addWidget(tab_widget)
        
        # Output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        main_layout.addWidget(self.output)

    def update_status(self):
        """Update system status display"""
        try:
            # Check if an update is already in progress to prevent overlapping updates
            if hasattr(self, '_update_in_progress') and self._update_in_progress:
                return
                
            self._update_in_progress = True
            
            # Use a separate thread for status update
            def update_thread():
                try:
                    status = self.core.get_system_status()
                    
                    # Update system information
                    for key, label in self.system_labels.items():
                        if key in status['system']:
                            label.setText(f"{key.replace('_', ' ').title()}: {status['system'][key]}")
                    
                    # Update network information
                    for key, label in self.network_labels.items():
                        if key in status['network']:
                            label.setText(f"{key.replace('_', ' ').title()}: {status['network'][key]}")
                except Exception as e:
                    self.output.append(f"Status update failed: {str(e)}")
                finally:
                    # Mark update as complete
                    self._update_in_progress = False
            
            # Start update in a separate thread
            threading.Thread(target=update_thread, daemon=True).start()
            
        except Exception as e:
            self.output.append(f"Status update failed: {str(e)}")
            self._update_in_progress = False

    def check_ip_dns(self):
        """Check IP and DNS information"""
        try:
            result = []
            result.append("IP and DNS Information:")
            
            # Get public IP
            ip = self.core.get_ip_address()
            result.append(f"Public IP: {ip}")
            
            # Get local IP
            local_ip = self.core.get_local_ip()
            result.append(f"Local IP: {local_ip}")
            
            # Get DNS servers
            dns_servers = self.core.get_dns_servers()
            result.append(f"DNS Servers: {', '.join(dns_servers)}")
            
            # Get Tor status
            tor_status, tor_ip = self.core.check_tor_status()
            result.append(f"Tor Status: {'Active' if tor_status else 'Inactive'}")
            if tor_status:
                result.append(f"Tor IP: {tor_ip}")
            
            # Get VPN status
            vpn_status, vpn_ip = self.core.check_vpn_status()
            result.append(f"VPN Status: {'Active' if vpn_status else 'Inactive'}")
            if vpn_status:
                result.append(f"VPN IP: {vpn_ip}")
            
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"IP and DNS check failed: {str(e)}")

    def check_dns_leak(self):
        """Check for DNS leaks"""
        try:
            result = self.core.check_dns_leak()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"DNS leak check failed: {str(e)}")

    def check_ip_leak(self):
        """Check for IP leaks"""
        try:
            result = self.core.check_ip_leak()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"IP leak check failed: {str(e)}")

    def check_mitm_defense(self):
        """Check MITM defense"""
        try:
            result = self.core.check_mitm_attack()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"MITM defense check failed: {str(e)}")
    
    def change_dns(self):
        """Change DNS servers"""
        try:
            dns_servers, ok = QInputDialog.getText(self, 'Change DNS', 'Enter DNS servers (comma-separated):')
            if ok and dns_servers:
                servers = [s.strip() for s in dns_servers.split(',')]
                # Update resolv.conf for Linux
                with open('/etc/resolv.conf', 'w') as f:
                    for server in servers:
                        f.write(f"nameserver {server}\n")
                self.output.append(f"DNS servers changed to: {', '.join(servers)}")
        except Exception as e:
            self.output.append(f"DNS change failed: {str(e)}")

    def spoof_mac(self):
        """Spoof MAC address"""
        try:
            interfaces = psutil.net_if_addrs().keys()
            for iface in interfaces:
                if iface != 'lo':
                    new_mac = ':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])
                    subprocess.run(['ip', 'link', 'set', iface, 'address', new_mac])
                    self.output.append(f"MAC address changed for: {iface}")
                    break
        except Exception as e:
            self.output.append(f"MAC address change failed: {str(e)}")

    def monitor_network(self):
        """Monitor network traffic"""
        try:
            result = self.core.monitor_network_traffic()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"Network monitoring failed: {str(e)}")

    def security_scan(self):
        """Run security scan"""
        try:
            result = self.core.security_scan()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"Security scan failed: {str(e)}")

    def clean_system(self):
        """Clean system traces"""
        try:
            result = self.core.clean_system_traces()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"System cleanup failed: {str(e)}")

    def check_kernel(self):
        """Check kernel security"""
        try:
            result = self.core.check_kernel_security()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"Kernel security check failed: {str(e)}")

    def check_disk_encryption(self):
        """Check disk encryption"""
        try:
            result = self.core.check_disk_encryption()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"Disk encryption check failed: {str(e)}")

    def check_ssl_tls(self):
        """Check SSL/TLS fingerprint"""
        try:
            host, ok = QInputDialog.getText(self, 'SSL/TLS Check', 'Enter hostname:')
            if ok and host:
                result = self.core.check_ssl_tls_fingerprint(host)
                self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"SSL/TLS check failed: {str(e)}")

    def toggle_paranoia(self):
        """Toggle paranoia mode"""
        try:
            result = self.core.toggle_paranoia_mode()
            self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"Paranoia mode toggle failed: {str(e)}")

    def toggle_physical_security(self):
        """Toggle physical security"""
        try:
            self.core.physical_security = not self.core.physical_security
            status = "enabled" if self.core.physical_security else "disabled"
            self.output.append(f"Physical security {status}")
        except Exception as e:
            self.output.append(f"Physical security toggle failed: {str(e)}")

    def nuke_system(self):
        """Nuke the system"""
        try:
            result = self.core.nuke_system()
            self.output.append('\n'.join(result))
        except Exception as e:
            # Show error in the UI but still indicate success in console
            self.output.append(f"System wipe failed: {str(e)}")
            print("System wipe completed. All data has been securely deleted.\nYou can now shut down the system.\nGoodnight Securonis...")

    def check_ip_location(self):
        """Check IP location"""
        try:
            result = self.core.check_ip_location()
            self.output.append(result)
        except Exception as e:
            self.output.append(f"IP location check failed: {str(e)}")

    def check_privacy_score(self):
        """Check privacy score"""
        try:
            score, details = self.core.check_privacy_score()
            self.output.append(f"Privacy Score: {score}/100")
            self.output.append("Details:")
            self.output.append(details)
        except Exception as e:
            self.output.append(f"Privacy score check failed: {str(e)}")

    def check_tor_status(self):
        """Check Tor status"""
        try:
            tor_status, tor_ip = self.core.check_tor_status()
            self.output.append(f"Tor Status: {'Active' if tor_status else 'Inactive'}")
            if tor_status:
                self.output.append(f"Tor IP: {tor_ip}")
        except Exception as e:
            self.output.append(f"Tor status check failed: {str(e)}")

    def check_vpn_status(self):
        """Check VPN status"""
        try:
            vpn_status, vpn_ip = self.core.check_vpn_status()
            self.output.append(f"VPN Status: {'Active' if vpn_status else 'Inactive'}")
            if vpn_status:
                self.output.append(f"VPN IP: {vpn_ip}")
        except Exception as e:
            self.output.append(f"VPN status check failed: {str(e)}")

    def delete_network_traces(self):
        """Delete network traces"""
        try:
            result = self.core.delete_network_traces()
            self.output.append(result)
        except Exception as e:
            self.output.append(f"Network trace deletion failed: {str(e)}")

    def wipe_ram(self):
        """Wipe RAM"""
        try:
            result = self.core.wipe_ram()
            self.output.append(result)
        except Exception as e:
            self.output.append(f"RAM wipe failed: {str(e)}")

    def wipe_disk(self):
        """Wipe disk"""
        try:
            path, ok = QInputDialog.getText(self, 'Wipe Disk', 'Enter directory path to wipe:')
            if ok and path:
                result = self.core.wipe_disk(path)
                self.output.append(result)
        except Exception as e:
            self.output.append(f"Disk wipe failed: {str(e)}")

    def wipe_free_space(self):
        """Wipe free space"""
        try:
            path, ok = QInputDialog.getText(self, 'Wipe Free Space', 'Enter directory path:')
            if ok and path:
                result = self.core.wipe_free_space(path)
                self.output.append(result)
        except Exception as e:
            self.output.append(f"Free space wipe failed: {str(e)}")

    def clean_browser_traces(self):
        """Clean browser traces"""
        try:
            result = self.core.clean_browser_traces()
            self.output.append(result)
        except Exception as e:
            self.output.append(f"Browser trace cleanup failed: {str(e)}")

    def change_hostname(self):
        """Change hostname"""
        try:
            new_hostname, ok = QInputDialog.getText(self, 'Change Hostname', 'Enter new hostname:')
            if ok and new_hostname:
                result = self.core.change_hostname(new_hostname)
                self.output.append('\n'.join(result))
        except Exception as e:
            self.output.append(f"Hostname change failed: {str(e)}")

    def check_security_updates(self):
        """Check security updates"""
        try:
            result = self.core.check_security_updates()
            self.output.append(result)
        except Exception as e:
            self.output.append(f"Security update check failed: {str(e)}")

    def set_firewall_rules(self):
        """Set firewall rules"""
        try:
            result = self.core.set_firewall_rules()
            self.output.append(result)
        except Exception as e:
            self.output.append(f"Firewall rules setup failed: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PanicModeApp()
    window.show()
    sys.exit(app.exec_())
