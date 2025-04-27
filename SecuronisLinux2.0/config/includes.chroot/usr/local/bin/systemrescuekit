#!/bin/bash

# ASCII art
function show_ascii_art() {
    cat << "EOF"
=========================================

                                   ____________________________
  _____                          ,\\    ___________________    \
 |     `------------------------'  ||  (___________________)   |
 |_____.------------------------.  ||  ____________________    |
                                 `//__(____________________)___/
                                         
=========================================
Securonis Linux - System Rescue Toolkit
EOF
    echo
}

# Tool list and descriptions
declare -A tools=(
    ["testdisk"]="Recover lost partitions and repair disk structures."
    ["photorec"]="Recover files from damaged disks (comes with testdisk)."
    ["gpart"]="Analyze and recover damaged partition tables."
    ["gparted"]="Graphical interface for partitioning and recovery."
    ["boot-repair"]="Automatically fix GRUB and MBR boot issues."
    ["e2fsprogs"]="Tools for ext2/3/4 file systems, including fsck."
    ["ntfs-3g"]="Full read/write support for NTFS file systems."
    ["dosfstools"]="Tools for FAT16/FAT32 file systems."
    ["extundelete"]="Recover deleted files from ext3/ext4 file systems."
    ["scalpel"]="Recover lost files from disk images."
    ["foremost"]="Recover data from damaged disks using file carving."
    ["ddrescue"]="Recover data from damaged disks and copy to another disk."
    ["partclone"]="Backup and restore specific partitions."
    ["clonezilla"]="Disk/system cloning and backup."
    ["busybox"]="Provides a lightweight recovery shell environment."
    ["systemrescue"]="Includes various tools for system recovery."
    ["chntpw"]="Reset local user passwords on Windows systems."
    ["iperf3"]="Network performance testing."
    ["nmap"]="Network scanning and device discovery."
)

# Function to install a tool
function install_tool() {
    local tool=$1
    echo "Installing $tool..."
    apt-get install -y "$tool"
}

# Function to install tools in a category
function install_category() {
    local category_tools=("$@")
    echo "Installing selected tools..."
    for tool in "${category_tools[@]}"; do
        install_tool "$tool"
    done
}

# Menu function
function show_menu() {
    echo "System Rescue Toolkit"
    echo "1) Disk and File System Tools"
    echo "2) Boot Recovery Tools"
    echo "3) File System Repair"
    echo "4) Data Recovery Tools"
    echo "5) Disk Cloning and Imaging"
    echo "6) General System Recovery Tools"
    echo "7) Network Recovery and Testing"
    echo "8) Install All"
    echo "9) Help"
    echo "0) Exit"
    echo -n "Make your selection: "
}

# Submenu function
function show_submenu() {
    local category_name=$1
    shift
    local category_tools=("$@")
    echo "$category_name:"
    for i in "${!category_tools[@]}"; do
        echo "$((i + 1))) ${category_tools[$i]}"
    done
    echo "$(( ${#category_tools[@]} + 1 ))) Install all"
    echo "$(( ${#category_tools[@]} + 2 ))) Go back"
    echo -n "Make your selection: "
    read sub_choice
    if (( sub_choice >= 1 && sub_choice <= ${#category_tools[@]} )); then
        install_tool "${category_tools[$((sub_choice - 1))]}"
    elif (( sub_choice == ${#category_tools[@]} + 1 )); then
        install_category "${category_tools[@]}"
    else
        echo "Returning to main menu..."
    fi
}

# Main loop
show_ascii_art
while true; do
    show_menu
    read choice
    case $choice in
        1)
            show_submenu "Disk and File System Tools" "testdisk" "photorec" "gpart" "gparted"
            ;;
        2)
            show_submenu "Boot Recovery Tools" "boot-repair"
            ;;
        3)
            show_submenu "File System Repair" "e2fsprogs" "ntfs-3g" "dosfstools"
            ;;
        4)
            show_submenu "Data Recovery Tools" "extundelete" "scalpel" "foremost"
            ;;
        5)
            show_submenu "Disk Cloning and Imaging" "ddrescue" "partclone" "clonezilla"
            ;;
        6)
            show_submenu "General System Recovery Tools" "busybox" "systemrescue" "chntpw"
            ;;
        7)
            show_submenu "Network Recovery and Testing" "iperf3" "nmap"
            ;;
        8)
            echo "Updating system..."
            apt-get update -y
            install_category "${!tools[@]}"
            ;;
        9)
            echo "Tool descriptions:"
            for tool in "${!tools[@]}"; do
                echo "$tool: ${tools[$tool]}"
            done
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid selection!"
            ;;
    esac
done
