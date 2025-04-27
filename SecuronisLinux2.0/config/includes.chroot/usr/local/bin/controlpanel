#!/bin/sh

print_usage() {
    echo "Usage: $0 {sysinfo|hwinfo|privacy|netinfo|diskinfo|procs|services|power|about}"
}

sys_info() {
    echo "== System Information =="
    echo "Hostname: $(hostname)"
    echo "OS: $(awk -F= '/^NAME/ {print $2}' /etc/os-release | tr -d '"') $(awk -F= '/^VERSION=/ {print $2}' /etc/os-release | tr -d '"')"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime -p)"
    echo "Last Boot: $(who -b | awk '{print $3, $4}')"
    echo "System Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Timezone: $(timedatectl show --property=Timezone --value)"
    echo "Desktop Environment: ${XDG_CURRENT_DESKTOP:-N/A}"
    echo "Display Manager: $(basename $(cat /etc/X11/default-display-manager 2>/dev/null) 2>/dev/null || echo N/A)"
    echo "Shell: $SHELL"
    echo "Language: ${LANG:-N/A}"
    cpu_idle=$(top -bn1 | grep "Cpu(s)" | sed 's/.*, *\([0-9.]*\)%* id.*/\1/')
    echo "CPU Usage: $(printf '%.1f%%' "$(echo "100 - $cpu_idle" | bc -l)")"
    echo "Memory Usage: $(free | awk '/Mem:/ {printf("%.1f%%", $3/$2*100)}')"
    echo "Swap Usage: $(free | awk '/Swap:/ {printf("%.1f%%", $3/$2*100)}')"
    if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
        echo "CPU Temp: $(awk '{printf("%.1f°C", $1/1000)}' /sys/class/thermal/thermal_zone0/temp)"
    else
        echo "CPU Temp: N/A"
    fi
    echo "Load Average: $(awk '{print $1, $2, $3}' /proc/loadavg)"
    if command -v acpi >/dev/null; then
        echo "Battery: $(acpi -b | awk -F', ' '{print $2}')"
    else
        echo "Battery: N/A"
    fi
    echo "---------------"
}

hw_info() {
    echo "== Hardware Information =="
    lscpu | grep -E 'Model name|Vendor ID|CPU(s)|Thread|MHz|Cache'
    echo "GPU:"
    if command -v lshw >/dev/null; then
        lshw -C display | grep 'product'
    else
        lspci | grep -i 'vga\|3d\|display'
    fi
    echo "RAM Details:"
    free -h | awk '/Mem:/ {print "Total: "$2", Used: "$3", Free: "$4}'
    echo "---------------"
}

privacy_status() {
    echo "== Privacy Status =="
    echo "Firewall (ufw): $(ufw status 2>/dev/null | head -n1 || echo 'ufw not installed')"
    echo "VPN: $(ip link show up | grep -E 'tun0|wg0' >/dev/null && echo Active || echo Inactive)"
    echo "Tor: $(systemctl is-active tor 2>/dev/null || echo inactive)"
    echo "DNS Servers: $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | paste -sd ',')"
    echo "Network Encryption: $(openssl version 2>/dev/null || echo 'openssl not available')"
    echo "DNS-over-TLS: $(grep -q '^DNSOverTLS=yes' /etc/systemd/resolved.conf 2>/dev/null && echo Enabled || echo Disabled)"
    echo "Updates: $(apt list --upgradable 2>/dev/null | grep -v Listing | wc -l) packages upgradable"
    echo "Antivirus (clamav): $(systemctl is-active clamav-daemon 2>/dev/null || echo inactive)"
    echo "SELinux: $(getenforce 2>/dev/null || echo N/A)"
    echo "AppArmor: $(aa-status 2>/dev/null | grep -q loaded && echo Active || echo Inactive)"
    echo "Kernel ASLR: $(sysctl kernel.randomize_va_space | awk '{print $3}')"
    echo "USB Protection: $(lsusb >/dev/null && echo Active || echo Inactive)"
    echo "SSH Status: $(systemctl is-active ssh 2>/dev/null || echo inactive)"
    echo "Open Ports: $(ss -tuln | wc -l) listening"
    echo "---------------"
}

net_info() {
    echo "== Network Information =="
    iface=$(ip route get 8.8.8.8 | awk '{print $5}')
    echo "Active Interface: $iface"
    echo "IP Address: $(hostname -I | awk '{print $1}')"
    echo "Public IP: $(curl -s ifconfig.me)"
    echo "DNS Servers: $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | paste -sd ',')"
    echo "Gateway: $(ip route | awk '/default/ {print $3}')"
    echo "MTU: $(ip link show $iface | awk '/mtu/ {print $5}')"
    echo "Interface Speed: $(cat /sys/class/net/$iface/speed 2>/dev/null || echo N/A) Mbps"
    echo "Firewall Rules: $(iptables -L --line-numbers 2>/dev/null | wc -l) rules"
    echo "Open Ports:"
    ss -tuln
    echo "VPN Status: $(ip link show up | grep -E 'tun0|wg0' >/dev/null && echo Active || echo Inactive)"
    echo "Network Encryption: $(openssl version 2>/dev/null || echo N/A)"
    echo "---------------"
}

disk_info() {
    echo "== Disk Information =="
    df -h --output=source,size,used,avail,pcent | tail -n +2
    echo "---------------"
}

procs() {
    echo "== Top 5 Processes by CPU Usage =="
    ps aux --sort=-%cpu | head -n 6
    echo "---------------"
}

services() {
    echo "== Active Services =="
    systemctl list-units --type=service --state=running
    echo "---------------"
}

power_info() {
    echo "== Power Information =="
    if command -v acpi >/dev/null; then
        acpi -b
    fi
    echo "CPU Frequency: $(lscpu | awk -F: '/MHz/ {print $2}')"
    echo "---------------"
}

about() {
    echo "Securonis Linux System Control Panel CLI"
    echo "This tool is specifically designed for Debian Linux systems."
    echo "---------------"
}

if [ $# -eq 0 ]; then
    print_usage
    exit 1
fi

case "$1" in
    sysinfo) sys_info ;;
    hwinfo) hw_info ;;
    privacy) privacy_status ;;
    netinfo) net_info ;;
    diskinfo) disk_info ;;
    procs) procs ;;
    services) services ;;
    power) power_info ;;
    about) about ;;
    *) print_usage ;;
esac
