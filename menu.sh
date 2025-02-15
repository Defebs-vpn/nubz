#!/bin/bash
# VPN Manager Menu Script
# Created by Defebs-vpn
# Created at: 2025-02-15 06:25:09 UTC

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to check if user exists
user_exists() {
    id "$1" &>/dev/null
    return $?
}

# Show banner
show_banner() {
    clear
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${GREEN}               VPN MANAGER MENU                   ${NC}"
    echo -e "${GREEN}            Created by Defebs-vpn                ${NC}"
    echo -e "${BLUE}=================================================${NC}"
    echo -e "Current Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
    echo -e "${BLUE}=================================================${NC}"
}

# Main menu
show_menu() {
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
create_user() {
    read -p "Enter username: " username
    
    if user_exists "$username"; then
        echo -e "${RED}Error: User $username already exists!${NC}"
        return 1
    fi
    
    read -s -p "Enter password: " password
    echo
    read -s -p "Confirm password: " password2
    echo
    
    if [ "$password" != "$password2" ]; then
        echo -e "${RED}Error: Passwords do not match!${NC}"
        return 1
    fi
    
    read -p "Enter expiry days [30]: " exp_days
    exp_days=${exp_days:-30}
    
    exdate=$(date -d "+${exp_days} days" '+%Y-%m-%d')
    useradd -m -s /bin/false -e "$exdate" "$username" || {
        echo -e "${RED}Error creating user!${NC}"
        return 1
    }
    
    echo "$username:$password" | chpasswd
    echo -e "${GREEN}User $username created successfully!${NC}"
    echo -e "Username: $username"
    echo -e "Password: $password"
    echo -e "Expiry Date: $exdate"
}

# Delete user account
delete_user() {
    read -p "Enter username to delete: " username
    
    if ! user_exists "$username"; then
        echo -e "${RED}Error: User $username does not exist!${NC}"
        return 1
    fi
    
    read -p "Are you sure you want to delete user $username? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        userdel -r "$username" || {
            echo -e "${RED}Error deleting user!${NC}"
            return 1
        }
        echo -e "${GREEN}User $username deleted successfully!${NC}"
    else
        echo -e "${YELLOW}Operation cancelled${NC}"
    fi
}

# View user list with improved formatting
view_users() {
    echo -e "\n${YELLOW}=== USER LIST ===${NC}"
    printf "%-20s %-20s %-15s\n" "Username" "Expiry Date" "Status"
    echo -e "------------------------------------------------------------"
    
    for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
        exp=$(chage -l "$user" | grep "Account expires" | cut -d: -f2-)
        status="Active"
        if [[ $(passwd -S "$user" | cut -d' ' -f2) == "L" ]]; then
            status="${RED}Locked${NC}"
        fi
        printf "%-20s %-20s %-15s\n" "$user" "$(echo $exp | xargs)" "$status"
    done
}

# Monitor user login with improved output
monitor_login() {
    echo -e "\n${YELLOW}=== ACTIVE USERS ===${NC}"
    printf "%-15s %-15s %-20s %-15s\n" "Username" "IP Address" "Login Time" "Connection"
    echo -e "------------------------------------------------------------"
    
    # Combine SSH and Dropbear connections
    (who; netstat -antp | grep ':22\|:143' | grep ESTABLISHED) | \
    awk '{
        if (NF > 3) {
            if ($1 == "tcp") {
                split($5, ip, ":");
                printf "%-15s %-15s %-20s %-15s\n", "-", ip[1], "Now", "Dropbear"
            } else {
                printf "%-15s %-15s %-20s %-15s\n", $1, $5, $3" "$4, "SSH"
            }
        }
    }'
}

# Check service status with improved formatting
check_services() {
    echo -e "\n${YELLOW}=== SERVICE STATUS ===${NC}"
    printf "%-20s %-15s %-20s\n" "Service" "Status" "Port"
    echo -e "------------------------------------------------------------"
    
    services=("ssh" "dropbear" "stunnel4" "ws-dropbear" "badvpn")
    
    for service in "${services[@]}"; do
        status=$(systemctl is-active "$service")
        port=""
        
        case $service in
            "ssh") port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}') ;;
            "dropbear") port=$(grep "DROPBEAR_PORT" /etc/default/dropbear | cut -d= -f2) ;;
            "stunnel4") port=$(grep "accept = " /etc/stunnel/stunnel.conf | head -1 | awk '{print $3}') ;;
            "ws-dropbear") port="80" ;;
            "badvpn") port="7300" ;;
        esac
        
        if [ "$status" == "active" ]; then
            printf "%-20s ${GREEN}%-15s${NC} %-20s\n" "$service" "ACTIVE" "$port"
        else
            printf "%-20s ${RED}%-15s${NC} %-20s\n" "$service" "INACTIVE" "$port"
        fi
    done
}

# Restart all services with progress
restart_services() {
    echo -e "\n${YELLOW}Restarting all services...${NC}"
    services=("ssh" "dropbear" "stunnel4" "ws-dropbear" "badvpn")
    total=${#services[@]}
    current=0
    
    for service in "${services[@]}"; do
        ((current++))
        echo -ne "Progress: [$current/$total] Restarting $service..."
        systemctl restart "$service" &>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAILED${NC}"
        fi
        sleep 1
    done
    echo -e "${GREEN}All services restarted successfully!${NC}"
}

# Speed test with fallback
speed_test() {
    echo -e "\n${YELLOW}Running speed test...${NC}"
    if command -v speedtest-cli &>/dev/null; then
        speedtest-cli
    else
        echo -e "${YELLOW}Installing speedtest-cli...${NC}"
        apt install -y speedtest-cli
        speedtest-cli
    fi
}

# System information with improved formatting
system_info() {
    echo -e "\n${YELLOW}=== SYSTEM INFORMATION ===${NC}"
    echo -e "OS\t\t: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo -e "Kernel\t\t: $(uname -r)"
    echo -e "CPU\t\t: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
    echo -e "Memory\t\t: $(free -h | grep Mem | awk '{print $2}') total, $(free -h | grep Mem | awk '{print $4}') free"
    echo -e "Disk Usage\t: $(df -h / | awk 'NR==2 {print $3"/"$2" ("$5" used)"}'"
    echo -e "Uptime\t\t: $(uptime -p)"
    echo -e "Load Average\t: $(uptime | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "IP Address\t: $(curl -s ifconfig.me)"
}

# Main script execution
show_banner
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
    
    echo -e "\nPress Enter to continue..."
    read
done
