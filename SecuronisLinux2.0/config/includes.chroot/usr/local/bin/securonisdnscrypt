#!/bin/bash

# Securonis Linux - DNSCrypt Manager

set -e

# ASCII Art Function
ascii_art() {
    cat << "EOF"
 ____                                  _     _     _                         
/ ___|  ___  ___ _   _ _ __ ___  _ __ (_)___| |   (_)_ __  _   ___  __       
\___ \ / _ \/ __| | | | '__/ _ \| '_ \| / __| |   | | '_ \| | | \ \/ /       
 ___) |  __/ (__| |_| | | | (_) | | | | \__ \ |___| | | | | |_| |>  <        
|____/ \___|\___|\__,_|_|  \___/|_| |_|_|___/_____|_|_| |_|\__,_/_/\_\       
 ____  _   _ ____   ____                  _        ____                      
|  _ \| \ | / ___| / ___|_ __ _   _ _ __ | |_     |  _ \ _ __ _____  ___   _ 
| | | |  \| \___ \| |   | '__| | | | '_ \| __|____| |_) | '__/ _ \ \/ / | | |
| |_| | |\  |___) | |___| |  | |_| | |_) | ||_____|  __/| | | (_) >  <| |_| |
|____/|_| \_|____/ \____|_|   \__, | .__/ \__|    |_|   |_|  \___/_/\_\\__, |
                              |___/|_|                                 |___/ 
                              
EOF
}

# Menu Function
menu() {
    ascii_art
    echo -e "\e[32m[Securonis Linux - DNSCrypt Manager]\e[0m"
    echo "1) Start DNSCrypt"
    echo "---------------------"
    echo "2) Set DNSCrypt Service"
    echo "3) Restart DNSCrypt Service"
    echo "4) Remove DNSCrypt Service"
    echo "---------------------"
    echo "5) Check DNSCrypt"
    echo "6) Check DNSCrypt Service Status"
    echo "--------------------"
    echo "7) Exit"
}


enable_dnscrypt() {
    echo "[+] Checking DNSCrypt configuration..."
    cd /etc/dnscrypt-proxy
    sudo dnscrypt-proxy -check

    echo "[+] Starting DNSCrypt proxy manually..."
    sudo dnscrypt-proxy 

    echo "[+] Checking if DNSCrypt proxy is running..."
    sudo dnscrypt-proxy -resolve example.com
}

# Enable DNSCrypt Service
set_systemd_service() {
    echo "[+] Installing DNSCrypt service..."
    cd /etc/dnscrypt-proxy
    sudo dnscrypt-proxy -service install

    echo "[+] Starting DNSCrypt service..."
    sudo dnscrypt-proxy -service start 
}

# Restart DNSCrypt Service
restart_systemd_service() {
    echo "[+] Restarting DNSCrypt service..."
    cd /etc/dnscrypt-proxy
    sudo dnscrypt-proxy -service restart
}

# Remove DNSCrypt Service
remove_systemd_service() {
    echo "[+] Stopping DNSCrypt service..."
    cd /etc/dnscrypt-proxy
    sudo dnscrypt-proxy -service stop

    echo "[+] Uninstalling DNSCrypt service..."
    sudo dnscrypt-proxy -service uninstall
}

# Check DNSCrypt Status
check_dnscrypt_status() {
    echo "[+] DNSCrypt Service Status:"
    sudo systemctl status dnscrypt-proxy 
}

# Check DNSCrypt
check_dnscrypt() {
    echo "[+] Checking DNSCrypt configuration..."
    cd /etc/dnscrypt-proxy
    sudo dnscrypt-proxy -check

    echo "[+] Listing available DNS servers..."
    sudo dnscrypt-proxy -list

    echo "[+] Resolving example.com using DNSCrypt..."
    sudo dnscrypt-proxy -resolve example.com
}

# Main Menu Loop
while true; do
    menu
    read -p "Enter your choice: " choice

    case $choice in
        1) enable_dnscrypt ;;
        2) set_systemd_service ;;
        3) restart_systemd_service ;;
        4) remove_systemd_service ;;
        5) check_dnscrypt ;;
        6) check_dnscrypt_status ;;
        7) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice! Please select a valid option." ;;
    esac

    echo -e "\nPress any key to continue..."
    read -n 1 -s -r
done
