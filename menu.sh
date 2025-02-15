#!/bin/bash
# VPN Manager Menu Script
# Created by Defebs-vpn
# Created at: 2025-02-14 21:14:21

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Show banner
clear
echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}               VPN MANAGER MENU                   ${NC}"
echo -e "${GREEN}            Created by Defebs-vpn                ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo -e "Current Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
echo -e "${BLUE}=================================================${NC}"

# Main menu
show_menu(){
    echo -e "\n${YELLOW}=== MAIN MENU ===${NC}"
    echo -e "1.  Create User Account"
    echo -e "2.  Delete User Account"
    echo -e "3.  View User List"
    echo -e "4.  Monitor User Login"
    echo -e "5.  Check Service Status"
    echo -e "6.  Restart All Services"
    echo -e "7.  Speed Test"
    echo -e "8.  System Information"
    echo -e "9.  Bandwidth Monitor"
    echo -e "10. Change Port"
    echo -e "11. Backup Configuration"
    echo -e "12. Restore Configuration"
    echo -e "13. Update Script"
    echo -e "0.  Exit"
    echo -e "${BLUE}=================================================${NC}"
}

# Create user account
create_user(){
    read -p "Enter username: " username
    read -s -p "Enter password: " password
    echo
    exp_days=30
    exdate=$(date -d "+${exp_days} days" '+%Y-%m-%d')
    useradd -m -s /bin/false -e "$exdate" "$username"
    echo -e "$password\n$password" | passwd "$username"
    echo -e "${GREEN}User $username created successfully!${NC}"
    echo -e "Expiry Date: $exdate"
}

# Delete user account
delete_user(){
    read -p "Enter username to delete: " username
    userdel -r "$username"
    echo -e "${GREEN}User $username deleted successfully!${NC}"
}

# View user list
view_users(){
    echo -e "\n${YELLOW}=== USER LIST ===${NC}"
    echo -e "Username\tExpiry Date"
    echo -e "------------------------"
    for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)
    do
        exp=$(chage -l "$user" | grep "Account expires" | cut -d: -f2)
        echo -e "$user\t\t$exp"
    done
}

# Monitor user login
monitor_login(){
    echo -e "\n${YELLOW}=== ACTIVE USERS ===${NC}"
    echo -e "Username\tIP Address\tLogin Time"
    echo -e "----------------------------------------"
    who | awk '{print $1"\t\t"$5"\t"$3" "$4}'
}

# Check service status
check_services(){
    echo -e "\n${YELLOW}=== SERVICE STATUS ===${NC}"
    services=("ssh" "dropbear" "stunnel4" "ws-dropbear" "badvpn")
    
    for service in "${services[@]}"
    do
        status=$(systemctl is-active "$service")
        if [ "$status" == "active" ]; then
            echo -e "$service\t[${GREEN}ACTIVE${NC}]"
        else
            echo -e "$service\t[${RED}INACTIVE${NC}]"
        fi
    done
}

# Restart all services
restart_services(){
    echo -e "\n${YELLOW}Restarting all services...${NC}"
    services=("ssh" "dropbear" "stunnel4" "ws-dropbear" "badvpn")
    
    for service in "${services[@]}"
    do
        systemctl restart "$service"
        echo -e "$service restarted"
    done
    echo -e "${GREEN}All services restarted successfully!${NC}"
}

# Speed test
speed_test(){
    echo -e "\n${YELLOW}Running speed test...${NC}"
    wget -qO- speedtest.net/speedtest-cli | bash
}

# System information
system_info(){
    echo -e "\n${YELLOW}=== SYSTEM INFORMATION ===${NC}"
    echo -e "OS\t: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo -e "Kernel\t: $(uname -r)"
    echo -e "CPU\t: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2)"
    echo -e "Memory\t: $(free -h | grep Mem | awk '{print $2}')"
    echo -e "Uptime\t: $(uptime -p)"
    echo -e "Load\t: $(uptime | awk -F'load average:' '{print $2}')"
}

# Bandwidth monitor
bandwidth_monitor(){
    echo -e "\n${YELLOW}=== BANDWIDTH USAGE ===${NC}"
    vnstat
}

# Change port
change_port(){
    echo -e "\n${YELLOW}=== CHANGE PORT ===${NC}"
    echo -e "1. SSH Port"
    echo -e "2. Dropbear Port"
    echo -e "3. SSL Port"
    echo -e "4. WebSocket Port"
    echo -e "0. Back to main menu"
    
    read -p "Select service: " choice
    case $choice in
        1) read -p "Enter new SSH port: " port
           sed -i "s/Port .*/Port $port/" /etc/ssh/sshd_config
           systemctl restart ssh
           ;;
        2) read -p "Enter new Dropbear port: " port
           sed -i "s/DROPBEAR_PORT=.*/DROPBEAR_PORT=$port/" /etc/default/dropbear
           systemctl restart dropbear
           ;;
        3) read -p "Enter new SSL port: " port
           sed -i "s/accept = .*/accept = $port/" /etc/stunnel/stunnel.conf
           systemctl restart stunnel4
           ;;
        4) read -p "Enter new WebSocket port: " port
           sed -i "s/LISTENING_PORT = .*/LISTENING_PORT = $port/" /usr/local/bin/ws-dropbear
           systemctl restart ws-dropbear
           ;;
        0) return
           ;;
        *) echo -e "${RED}Invalid option${NC}"
           ;;
    esac
}

# Backup configuration
backup_config(){
    backup_dir="/root/vpn_backup"
    backup_file="vpn_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    mkdir -p "$backup_dir"
    tar -czf "$backup_dir/$backup_file" \
        /etc/ssh/sshd_config \
        /etc/default/dropbear \
        /etc/stunnel/stunnel.conf \
        /usr/local/bin/ws-*
    
    echo -e "${GREEN}Backup created: $backup_dir/$backup_file${NC}"
}

# Restore configuration
restore_config(){
    backup_dir="/root/vpn_backup"
    
    if [ ! -d "$backup_dir" ]; then
        echo -e "${RED}No backup directory found!${NC}"
        return
    }
    
    echo -e "\n${YELLOW}Available backups:${NC}"
    ls -1 "$backup_dir"
    
    read -p "Enter backup file name to restore: " backup_file
    
    if [ -f "$backup_dir/$backup_file" ]; then
        tar -xzf "$backup_dir/$backup_file" -C /
        echo -e "${GREEN}Configuration restored successfully!${NC}"
        restart_services
    else
        echo -e "${RED}Backup file not found!${NC}"
    fi
}

# Update script
update_script(){
    echo -e "\n${YELLOW}Checking for updates...${NC}"
    wget -q -O /tmp/setup.sh https://raw.githubusercontent.com/Defebs-vpn/nubz/main/setup.sh
    
    if [ $? -eq 0 ]; then
        chmod +x /tmp/setup.sh
        /tmp/setup.sh update
        echo -e "${GREEN}Script updated successfully!${NC}"
    else
        echo -e "${RED}Update failed!${NC}"
    fi
}

# Main loop
while true; do
    show_menu
    read -p "Enter your choice [0-13]: " choice
    
    case $choice in
        1)  create_user ;;
        2)  delete_user ;;
        3)  view_users ;;
        4)  monitor_login ;;
        5)  check_services ;;
        6)  restart_services ;;
        7)  speed_test ;;
        8)  system_info ;;
        9)  bandwidth_monitor ;;
        10) change_port ;;
        11) backup_config ;;
        12) restore_config ;;
        13) update_script ;;
        0)  echo -e "${GREEN}Thank you for using VPN Manager!${NC}"
            exit 0 ;;
        *)  echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo -e "\nPress any key to continue..."
    read -n 1
done