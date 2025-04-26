#!/bin/bash

# Securonis Linux - System and Kernel Hardening
# Developer : root0emir

# Check if running in live mode
check_live_system() {
    if grep -q "overlayfs" /proc/mounts || grep -q "overlay" /proc/mounts || [ -f /usr/bin/ubiquity ] || [ -f /usr/bin/casper ]; then
        echo -e "\e[31m[!] WARNING: You appear to be running in a live environment!\e[0m"
        echo -e "\e[33m[!] If you plan to install this system later, remember to restore kernel settings to default before installation.\e[0m"
        echo -e "\e[33m[!] Otherwise, the installation process might fail.\e[0m"
        echo
        read -p "Press Enter to continue..."
    fi
}

# this script need a root permission
if [[ $EUID -ne 0 ]]; then
   echo "!-This script requires root permissions. Please run it with 'sudo'." 
   exit 1
fi

# Run live system check
check_live_system

# ASCII Art Function
ascii_art() {
    cat << "EOF"
    
           @@@@@@@@@@           
           @@      @@           
   @@@@@  @@@      @@@  @@@@@   
  @@@@@@@@@@        @@@@@@@@@@  
 @@@                        @@@ 
@@@         @@@@@@@@         @@@
@@@@      @@@@    @@@@      @@@@
  @@@@   @@@        @@@   @@@@  
   @@@   @@          @@   @@@   
  @@@@   @@@        @@@   @@@@  
@@@@      @@@@    @@@@      @@@@
@@@         @@@@@@@@         @@@
 @@@                        @@@ 
  @@@@@@@@@@        @@@@@@@@@@  
   @@@@@ @@@@      @@@@ @@@@@   
           @@      @@           
           @@@@@@@@@@           
EOF
}

# Menu Function
menu() {
    ascii_art
    echo -e "\e[32m[Securonis Linux - System and Kernel Hardening]\e[0m"
    echo "1) Enable Standard System Hardening"
    echo "2) Enable Maximum System Hardening"
    echo "3) Restore Default Kernel Settings"
    echo "4) Enable AppArmor"
    echo "5) Disable AppArmor"
    echo "6) Enable SELinux"
    echo "7) Disable SELinux"
    echo "8) Disable System Logs"
    echo "9) Enable System Logs"
    echo "10) Enable Firewall"
    echo "11) Disable Firewall"
    echo "12) Exit"
}

# Standard System Hardening
enable_standard_hardening() {
    echo "[+] Standard Kernel Hardening is Starting..."
    
    # Önce yedek alalım
    backup_config
    
    # Bağımlılıkları kontrol edelim
    check_dependencies
    
    # Dizinlerin varlığını kontrol edelim
    mkdir -p /etc/sysctl.d
    mkdir -p /etc/modprobe.d
    mkdir -p /etc/security/limits.d

    # Kernel ayarlarını uygula
    if ! sysctl --system; then
        echo "[!] Error applying sysctl settings"
        return 1
    fi

    echo "[*] This script developed by root0emir"

    # Kernel-level security settings
    cat <<EOF > /etc/sysctl.d/99-securonis-hardening.conf
# IPv4 Network Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# Memory Protection
kernel.randomize_va_space = 2
vm.mmap_min_addr = 65536
vm.swappiness = 30
vm.dirty_ratio = 30
vm.dirty_background_ratio = 10

# Kernel Security
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
kernel.sysrq = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

    # Apply settings
    sysctl --system

    # Basic module restrictions
    mkdir -p /etc/modprobe.d
    cat <<EOF > /etc/modprobe.d/secure.conf
# Disable unused filesystems
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
EOF

    # Set secure permissions
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group

    echo "[+] Verifying changes..."
    if ! sysctl -a | grep -q "kernel.randomize_va_space = 2"; then
        echo "[!] Warning: Some settings may not have been applied correctly"
    fi

    echo "[+] Standard Kernel Hardening Completed."
}

# Maximum System Hardening
enable_maximum_hardening() {
    echo "[+] Maximum Security Kernel Hardening is Starting..."
    echo "[*] Warning: This may affect system usability!"


    # Kernel-level security settings
    cat <<EOF > /etc/sysctl.d/99-securonis-hardening.conf
# IPv4 Network Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# net.ipv4.icmp_echo_ignore_all = 1  # Commented out to allow ping for network troubleshooting
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0

# IPv6 Security
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Memory Protection
kernel.randomize_va_space = 2
vm.mmap_min_addr = 65536
vm.swappiness = 10
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5
vm.panic_on_oom = 0

# Kernel Security
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
kernel.sysrq = 1
kernel.core_uses_pid = 1
kernel.panic = 10
kernel.panic_on_oops = 10
fs.protected_hardlinks = 0  
fs.protected_symlinks = 0   
fs.suid_dumpable = 0
# kernel.modules_disabled = 1  # Commented out as it prevents loading essential modules
dev.tty.ldisc_autoload = 1

# Additional Security
kernel.perf_event_paranoid = 2  
kernel.unprivileged_userns_clone = 0
EOF

    # Apply settings
    sysctl --system

    # Ensure modprobe.d directory exists to avoid "No such file or directory" errors
    mkdir -p /etc/modprobe.d

    # Strict module restrictions
    cat <<EOF > /etc/modprobe.d/secure.conf
# Disable unused filesystems
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
# install squashfs /bin/false  # Commented out as it may be needed for some systems
# install udf /bin/false       # Commented out as it may be needed for optical media

# Disable unused protocols
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false

# Disable unused devices - commented out to prevent hardware issues
# install usb-storage /bin/false    # Commented out to allow USB storage devices
# install firewire-core /bin/false  # Commented out to allow FireWire devices if needed
# install thunderbolt /bin/false    # Commented out to allow Thunderbolt devices if needed
EOF

    # Set strict permissions
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group

    # Configure strict system limits
    cat <<EOF > /etc/security/limits.d/99-security.conf
* hard core 0
* soft nproc 1024
* hard nproc 4096
* soft nofile 4096
* hard nofile 16384
EOF

    # Enable process accounting and auditing
    if ! systemctl is-active --quiet acct; then
        apt-get install -y acct auditd
        systemctl enable acct auditd
        systemctl start acct auditd
        
        # Strict audit rules
        cat <<EOF > /etc/audit/rules.d/99-security.rules
-D
-b 8192
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/pam.d/ -p wa -k pam
-w /etc/nsswitch.conf -p wa -k nsswitch
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k sudo_usage
EOF
        augenrules --load
    fi

    echo "[+] Maximum Security Kernel Hardening Completed."
    echo "[!] Warning: Some features may be restricted and system usability may be affected."
    echo "[!] Note: System reboot is recommended for all changes to take effect."
}

# Restore Default Kernel Settings
restore_default_kernel_settings() {
    echo "[!] Restoring default kernel settings..."
    # Remove custom hardening settings
    rm -f /etc/sysctl.d/99-securonis-hardening.conf
    rm -f /etc/modprobe.d/secure.conf

    # Apply default settings
    sysctl --system

    echo "[✔] Default kernel settings have been restored!"
}

# Enable AppArmor
enable_apparmor() {
    echo "[+] Enabling AppArmor..."
    systemctl start apparmor
    systemctl enable apparmor
    if command -v aa-enforce &> /dev/null; then
        aa-enforce /etc/apparmor.d/*
        echo "[✔] AppArmor has been enabled and configured!"
    else
        echo "AppArmor tools are not installed. Please install AppArmor tools first."
    fi
}

# Disable AppArmor
disable_apparmor() {
    echo "[!] Disabling AppArmor..."
    systemctl stop apparmor
    systemctl disable apparmor
    if command -v aa-disable &> /dev/null; then
        aa-disable /etc/apparmor.d/*
        echo "[✔] AppArmor has been disabled!"
    else
        echo "AppArmor tools are not installed."
    fi
}

# Enable SELinux
enable_selinux() {
    echo "[+] Enabling SELinux..."
    if [ -f /etc/selinux/config ]; then
        setenforce 1
        sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
        echo "[✔] SELinux has been enabled!"
    else
        echo "SELinux is not installed! Would you like to install SELinux? (y/n)"
        read -r install_selinux
        if [ "$install_selinux" == "y" ]; then
            apt-get install -y selinux-utils selinux-basics
            selinux-activate
            echo "SELinux has been installed and activated. Please reboot for changes to take effect."
        fi
    fi
}

# Disable SELinux
disable_selinux() {
    echo "[!] Disabling SELinux..."
    if [ -f /etc/selinux/config ]; then
        setenforce 0
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
        echo "[✔] SELinux has been disabled! System reboot is recommended for changes to take full effect."
    else
        echo "SELinux is not installed."
    fi
}

# Disable System Logs
disable_system_logs() {
    echo "[!] Disabling system logs..."
    systemctl stop rsyslog
    systemctl disable rsyslog
    systemctl stop systemd-journald
    systemctl disable systemd-journald

    # Clear existing logs
    rm -rf /var/log/*
    journalctl --vacuum-time=1s

    echo "[✔] System logs have been disabled!"
}

# Enable System Logs
enable_system_logs() {
    echo "[+] Enabling system logs..."
    systemctl start rsyslog
    systemctl enable rsyslog
    systemctl start systemd-journald
    systemctl enable systemd-journald

    echo "[✔] System logs have been enabled!"
}

# MACsec Encryption functionality has been removed

# Enable Firewall
enable_firewall() {
    echo "[+] Enabling firewall..."
    
    # UFW'nin yüklü olup olmadığını kontrol et
    if ! command -v ufw >/dev/null 2>&1; then
        echo "[!] UFW is not installed"
        read -p "Would you like to install UFW? (y/n): " install_ufw
        if [ "$install_ufw" == "y" ]; then
            apt-get update
            apt-get install -y ufw
        else
            echo "[!] Cannot proceed without UFW"
            return 1
        fi
    fi
    
    # Temel güvenlik kurallarını ekle
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH bağlantısını koru
    ufw allow ssh
    
    # UFW'yi etkinleştir
    echo "y" | ufw enable
    
    # Durumu kontrol et
    if ufw status | grep -q "Status: active"; then
        echo "[✔] Firewall enabled and configured!"
    else
        echo "[!] Failed to enable firewall"
        return 1
    fi
}

# Disable Firewall
disable_firewall() {
    echo "[!] Disabling firewall..."
    sudo ufw disable
    echo "[✔] Firewall disabled!"
}

# Main Menu Loop
while true; do
    menu
    read -p "Enter your choice: " choice

    case $choice in
        1) enable_standard_hardening ;;
        2) enable_maximum_hardening ;;
        3) restore_default_kernel_settings ;;
        4) enable_apparmor ;;
        5) disable_apparmor ;;
        6) enable_selinux ;;
        7) disable_selinux ;;
        8) disable_system_logs ;;
        9) enable_system_logs ;;
        10) enable_firewall ;;
        11) disable_firewall ;;
        12) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice! Please select a valid option.";;
    esac

    echo -e "\nPress any key to continue..."
    read -n 1 -s -r
done
