#!/bin/bash

# ASCII Art
cat << "EOF"

            _
 _         | |
| | _______| |---------------------------------------------\
| -)_______|==[]============================================>
|_|        | |---------------------------------------------/
           |_|     
                                      
EOF

echo "----------------------------------"
echo "  System Knight Security Scanner  "
echo "----------------------------------"
echo ""

# Function to install necessary tools
function install_tool() {
    tool=$1
    if ! command -v $tool &> /dev/null; then
        echo "Installing $tool..."
        sudo apt install -y $tool
        
        # Install clamav-daemon if the tool is clamav
        if [ "$tool" = "clamav" ]; then
            echo "Installing clamav-daemon..."
            sudo apt install -y clamav-daemon
        fi
    else
        echo "$tool is already installed."
    fi
}

# Function to perform a detailed security scan
function detailed_scan() {
    echo "Performing a detailed security scan..."
    install_tool clamav
    sudo freshclam
    sudo clamscan -r --bell -i --stdout --exclude-dir=/sys --exclude-dir=/proc /
    echo "Detailed security scan completed."
}

# Function to perform a quick security scan
function quick_scan() {
    echo "Performing a quick security scan..."
    install_tool clamav
    sudo freshclam
    sudo clamscan -r --bell -i --stdout /home
    echo "Quick security scan completed."
}

# Function to scan a specific file or directory
function scan_specific() {
    echo "Scan a specific file or directory..."
    install_tool clamav
    
    read -p "Enter the path to scan: " scan_path
    
    if [ ! -e "$scan_path" ]; then
        echo "Error: $scan_path does not exist."
        return
    fi
    
    echo "Scanning $scan_path..."
    sudo clamscan -r --bell -i --stdout "$scan_path"
    echo "Scan of $scan_path completed."
}

# Function to perform an offline security scan with chkrootkit
function offline_scan() {
    echo "Performing an offline security scan with chkrootkit..."
    install_tool chkrootkit
    sudo chkrootkit
    echo "Offline security scan completed."
}

# Function to perform an offline security scan with rkhunter
function rkhunter_scan() {
    echo "Performing a rootkit scan with rkhunter..."
    install_tool rkhunter
    sudo rkhunter --update
    sudo rkhunter --check --skip-keypress
    echo "Rootkit scan completed."
}

# Function to perform a malware scan with Maldet
function malware_scan() {
    echo "Performing a malware scan with Maldet..."
    
    # Check if maldet is already installed
    if command -v maldet &> /dev/null; then
        echo "Maldet is already installed."
    else
        echo "------------------------------------------------------"
        echo "Maldet is not installed."
        echo "Manual installation steps:"
        echo "1. Download the latest version:"
        echo "   wget http://www.rfxn.com/downloads/maldetect-current.tar.gz"
        echo "2. Extract the archive:"
        echo "   tar -xzf maldetect-current.tar.gz"
        echo "3. Enter the directory and run installer:"
        echo "   cd maldetect-*"
        echo "   sudo ./install.sh"
        echo "4. Once installed, run this scan option again."
        echo "------------------------------------------------------"
        read -p "Press Enter to return to the main menu..."
        return
    fi
    
    # Update malware definitions
    echo "Updating malware definitions..."
    sudo maldet -u
    
    # Scan home directory
    echo "Scanning home directory for malware..."
    sudo maldet -a 
    echo "Malware scan completed."
}

# Function to perform a memory scan for malware
function memory_scan() {
    echo "Performing a memory scan for malware..."
    install_tool clamav
    
    # Create a temporary script for process scanning
    echo "#!/bin/bash
echo \"Scanning running processes for malware...\"
for pid in \$(ps -ef | grep -v grep | awk '{print \$2}'); do
    if [ -d /proc/\$pid ]; then
        echo \"Scanning process \$pid\"
        sudo clamscan --quiet -r /proc/\$pid/fd/ 2>/dev/null
    fi
done
echo \"Memory scan complete.\"" > /tmp/clamscan_memory.sh
    
    # Make executable and run
    chmod +x /tmp/clamscan_memory.sh
    sudo /tmp/clamscan_memory.sh
    
    # Clean up
    rm /tmp/clamscan_memory.sh
}

# Function to perform a filesystem integrity check with AIDE
function integrity_check() {
    echo "Performing a filesystem integrity check with AIDE..."
    install_tool aide
    
    # Initialize AIDE if database doesn't exist
    if [ ! -f /var/lib/aide/aide.db ]; then
        echo "Initializing AIDE database (this may take a while)..."
        sudo aideinit
        sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
    
    # Run integrity check
    sudo aide --config=/etc/aide/aide.conf --check
    echo "Filesystem integrity check completed."
}

# Function to check for suspicious processes and services
function check_processes() {
    echo "Checking for suspicious processes and services..."
    echo "Processes using high resources:"
    ps aux | sort -nrk 3,3 | head -n 10
    
    echo -e "\nOpen network connections:"
    sudo lsof -i -P -n | grep LISTEN
    
    echo -e "\nUnusual SUID/SGID files:"
    sudo find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null | sort
    
    echo "Process check completed."
}

# Function to perform a vulnerability scan with Lynis
function vulnerability_scan() {
    echo "Performing a vulnerability scan with Lynis..."
    
    # Check if Lynis is installed
    if ! command -v lynis &> /dev/null; then
        install_tool lynis
    fi
    
    # Run Lynis directly - no wrapper needed in terminal mode
    sudo lynis audit system
    
    echo "Vulnerability scan completed."
}



# Function to display the main menu
function main_menu() {
    while true; do
        echo ""
        echo "System Knight Security Scanner - Main Menu:"
        echo "1. Detailed Security Scan"
        echo "2. Quick Security Scan"
        echo "3. Scan Specific File/Directory"
        echo "4. Offline Rootkit Scan (chkrootkit)"
        echo "5. Rootkit Scan (rkhunter)"
        echo "6. Malware Scan (Maldet)"
        echo "7. Memory Scan"
        echo "8. Filesystem Integrity Check (AIDE)"
        echo "9. Check Suspicious Processes"
        echo "10. Vulnerability Scan (Lynis)"
        echo "11. Exit"
        echo ""
        read -p "Choose an option [1-11]: " choice
        echo ""
        
        case $choice in
            1) detailed_scan ;;
            2) quick_scan ;;
            3) scan_specific ;;
            4) offline_scan ;;
            5) rkhunter_scan ;;
            6) malware_scan ;;
            7) memory_scan ;;
            8) integrity_check ;;
            9) check_processes ;;
            10) vulnerability_scan ;;
            11) echo "Exiting..."; exit 0 ;;
            *) echo "Invalid choice. Please try again." ;;
        esac
        
        # Pause before returning to menu
        echo ""
        read -p "Press Enter to return to the main menu..."
    done
}

# Start the script by displaying the main menu
main_menu

