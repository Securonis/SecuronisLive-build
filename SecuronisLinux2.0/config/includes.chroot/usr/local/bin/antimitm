#!/usr/bin/env python3

import scapy.all as scapy
import os
import sys
import signal
import subprocess
from datetime import datetime

def log_message(message):
    print(message)
    with open("antimitm.log", "a") as log_file:
        log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None
    except Exception as e:
        log_message(f"[!] Error getting MAC address for IP {ip}: {e}")
        return None

def block_attacker(ip):
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
        log_message(f"[+] Blocked attacker IP: {ip}")
    except subprocess.CalledProcessError as e:
        log_message(f"[!] Error blocking attacker IP {ip}: {e}")

def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    try:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        scapy.send(packet, count=4, verbose=False)
        log_message("[+] Network restored to its original state.")
    except Exception as e:
        log_message(f"[!] Error restoring network: {e}")

def process_packet(packet, gateway_ip, gateway_mac, target_ip, target_mac):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac and real_mac != response_mac:
                alert_msg = f"[!] ARP spoofing detected from IP: {packet[scapy.ARP].psrc}"
                log_message(alert_msg)
                log_message(f"    Real MAC: {real_mac}, Fake MAC: {response_mac}")
                block_attacker(packet[scapy.ARP].psrc)
                restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
            else:
                log_message(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No attack detected from IP: {packet[scapy.ARP].psrc}")
        except Exception as e:
            log_message(f"[!] Error processing packet: {e}")

def sniff_packets(interface, gateway_ip, gateway_mac, target_ip, target_mac):
    try:
        scapy.sniff(iface=interface, store=False, prn=lambda packet: process_packet(packet, gateway_ip, gateway_mac, target_ip, target_mac), filter="arp")
    except Exception as e:
        log_message(f"[!] Error sniffing packets on interface {interface}: {e}")

def get_network_info(interface):
    try:
        # Ağ arayüzünün aktif olup olmadığını kontrol et
        if not scapy.get_if_addr(interface):
            raise SystemExit(f"[!] The selected interface '{interface}' is not active or does not have an IP address.")

        gateway_ip = scapy.conf.route.route("0.0.0.0")[2]
        gateway_mac = get_mac(gateway_ip)
        if not gateway_mac:
            raise SystemExit("[!] Could not get gateway MAC address. Please check your network connection.")

        target_ip = scapy.get_if_addr(interface)
        target_mac = get_mac(target_ip)
        if not target_mac:
            raise SystemExit(f"[!] Could not get MAC address for the selected interface '{interface}'. Please check your network settings.")

        return gateway_ip, gateway_mac, target_ip, target_mac
    except Exception as e:
        raise SystemExit(f"[!] Error getting network information: {e}")

def list_interfaces():
    return scapy.get_if_list()

def select_interface():
    interfaces = list_interfaces()
    print("\nAvailable network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"[{idx + 1}] {iface}")
    while True:
        try:
            choice = int(input("Select a network interface: "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print("[!] Invalid choice. Please select a valid interface.")
        except ValueError:
            print("[!] Please enter a number.")

def signal_handler(sig, frame):
    print("\n[*] Stopping packet sniffing...")
    sys.exit(0)

def menu(interface=None):
    print("\n[1] Select Network Interface")
    if interface:
        print(f"[2] Start Sniffing (Current Interface: {interface})")
    else:
        print("[2] Start Sniffing (No Interface Selected)")
    print("[3] Stop Sniffing")
    print("[4] Exit")
    return input("Enter your choice: ")

def main():
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")

    signal.signal(signal.SIGINT, signal_handler)

    interface = None
    gateway_ip = None
    gateway_mac = None
    target_ip = None
    target_mac = None

    while True:
        choice = menu(interface)
        if choice == "1":
            interface = select_interface()
            print(f"[*] Selected network interface: {interface}")
            try:
                gateway_ip, gateway_mac, target_ip, target_mac = get_network_info(interface)
                print(f"[*] Gateway IP: {gateway_ip}, Gateway MAC: {gateway_mac}")
                print(f"[*] Target IP: {target_ip}, Target MAC: {target_mac}")
            except SystemExit as e:
                print(f"[!] Error: {e}")
                print("[!] Please ensure the selected interface is active and has an IP address.")
                interface = None  # Reset interface if network info fails
        elif choice == "2":
            if not interface:
                print("[!] Please select a network interface first.")
            else:
                print("[*] Starting packet sniffing...")
                sniff_packets(interface, gateway_ip, gateway_mac, target_ip, target_mac)
        elif choice == "3":
            if gateway_ip and gateway_mac and target_ip and target_mac:
                print("[*] Stopping packet sniffing...")
                restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
            else:
                print("[!] No active sniffing session to stop.")
        elif choice == "4":
            print("[*] Exiting...")
            if gateway_ip and gateway_mac and target_ip and target_mac:
                restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
