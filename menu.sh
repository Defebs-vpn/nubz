#!/bin/bash
# ==================================================================
# VPN Manager Menu Script
# Created by: Defebs-vpn
# Created at: 2025-02-15 08:01:44 UTC
# Version: 2.3.4
# ==================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to check system requirements
check_requirements() {
    echo -e "${YELLOW}Checking system requirements...${NC}"
    
    # List of required packages
    local required_packages=(
        "curl"
        "wget"
        "vnstat"
        "speedtest-cli"
        "jq"
        "netfilter-persistent"
        "iptables-persistent"
    )
    
    # Check and install missing packages
    local missing_packages=()
    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package"; then
            missing_packages+=("$package")
        fi
    done
    
    # Install missing packages if any
    if [ ${#missing_packages[@]} -ne 0 ]; then
        echo -e "${YELLOW}Installing missing packages: ${missing_packages[*]}${NC}"
        apt update &>/dev/null
        
        for package in "${missing_packages[@]}"; do
            echo -ne "${CYAN}Installing $package...${NC}"
            apt install -y "$package" &>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${RED}Failed${NC}"
            fi
        done
    fi
    
    # Check system services
    local required_services=(
        "ssh"
        "dropbear"
        "stunnel4"
        "ws-dropbear"
        "badvpn"
    )
    
    echo -e "\n${YELLOW}Checking system services...${NC}"
    for service in "${required_services[@]}"; do
        if systemctl is-active "$service" &>/dev/null; then
            echo -e "$service: ${GREEN}Active${NC}"
        else
            echo -e "$service: ${RED}Inactive${NC}"
        fi
    done
    
    # Check system resources
    echo -e "\n${YELLOW}Checking system resources...${NC}"
    local memory_usage=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')
    local disk_usage=$(df -h / | awk 'NR==2{print $5}')
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
    
    echo -e "Memory Usage : $memory_usage"
    echo -e "Disk Usage  : $disk_usage"
    echo -e "CPU Usage   : $cpu_usage%"
}

# Function to check root access
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Function to show current time
show_current_time() {
    echo -e "${CYAN}Date & Time : $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "Login as   : $(whoami)${NC}"
}

# Function to show banner
show_banner() {
    clear
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${PURPLE}    ____  _____ _____ _____ ____  ____      __     ______  _   _ ${NC}"
    echo -e "${PURPLE}   |  _ \|  ___|  ___| ____|  _ \/ ___|    \ \   / /  _ \| \ | |${NC}"
    echo -e "${PURPLE}   | | | | |_  | |_  |  _| | |_) \___ \     \ \ / /| |_) |  \| |${NC}"
    echo -e "${PURPLE}   | |_| |  _| |  _| | |___|  _ < ___) |     \ V / |  __/| |\  |${NC}"
    echo -e "${PURPLE}   |____/|_|   |_|   |_____|_| \_\____/       \_/  |_|   |_| \_|${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${GREEN}                   PREMIUM VPN MANAGER                          ${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${YELLOW}Server Information${NC}"
    echo -e "${CYAN}IP Address : $(curl -s ifconfig.me)"
    echo -e "Hostname   : $(hostname)${NC}"
    show_current_time
    echo -e "${BLUE}================================================================${NC}"
}

# Function to show menu
show_menu() {
    echo -e "\n${YELLOW}Main Menu${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${YELLOW}User Management${NC}"
    echo -e " ${GREEN}[1]${NC} • Create User Account"
    echo -e " ${GREEN}[2]${NC} • Delete User Account"
    echo -e " ${GREEN}[3]${NC} • View User List"
    echo -e " ${GREEN}[4]${NC} • Monitor User Login"
    echo -e "${BLUE}----------------------------------------------------------------${NC}"
    echo -e "${YELLOW}Service Management${NC}"
    echo -e " ${GREEN}[5]${NC} • Check Service Status"
    echo -e " ${GREEN}[6]${NC} • Restart All Services"
    echo -e " ${GREEN}[7]${NC} • Fix Inactive Services"
    echo -e " ${GREEN}[8]${NC} • Change Port"
    echo -e "${BLUE}----------------------------------------------------------------${NC}"
    echo -e "${YELLOW}System Tools${NC}"
    echo -e " ${GREEN}[9]${NC} • Speed Test"
    echo -e " ${GREEN}[10]${NC} • System Information"
    echo -e " ${GREEN}[11]${NC} • Bandwidth Monitor"
    echo -e "${BLUE}----------------------------------------------------------------${NC}"
    echo -e "${YELLOW}Backup & Update${NC}"
    echo -e " ${GREEN}[12]${NC} • Backup Configuration"
    echo -e " ${GREEN}[13]${NC} • Restore Configuration"
    echo -e " ${GREEN}[14]${NC} • Update Script"
    echo -e " ${RED}[0]${NC} • Exit"
    echo -e "${BLUE}================================================================${NC}"
    echo -e ""
    read -p "Select menu [0-14]: " choice
    echo -e ""
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

# System information with fixed syntax
system_info() {
    echo -e "\n${YELLOW}=== SYSTEM INFORMATION ===${NC}"
    echo -e "OS\t\t: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo -e "Kernel\t\t: $(uname -r)"
    echo -e "CPU\t\t: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
    echo -e "Memory\t\t: $(free -h | grep Mem | awk '{print $2}') total, $(free -h | grep Mem | awk '{print $4}') free"
    echo -e "Disk Usage\t: $(df -h / | awk 'NR==2 {print $3"/"$2" ("$5" used)"}')"
    echo -e "Uptime\t\t: $(uptime -p)"
    echo -e "Load Average\t: $(uptime | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "IP Address\t: $(curl -s ifconfig.me)"
}

# Bandwidth monitor function
bandwidth_monitor() {
    echo -e "\n${YELLOW}=== BANDWIDTH USAGE ===${NC}"
    if command -v vnstat &>/dev/null; then
        vnstat
    else
        echo -e "${YELLOW}Installing vnstat...${NC}"
        apt install -y vnstat
        systemctl enable vnstat
        systemctl start vnstat
        sleep 2
        vnstat
    fi
}

# Change port function
change_port() {
    echo -e "\n${YELLOW}=== CHANGE PORT ===${NC}"
    echo -e "1. SSH Port"
    echo -e "2. Dropbear Port"
    echo -e "3. SSL Port"
    echo -e "4. WebSocket Port"
    echo -e "0. Back to main menu"
    
    read -p "Select service: " choice
    case $choice in
        1) read -p "Enter new SSH port: " port
           if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
               sed -i "s/^Port .*/Port $port/" /etc/ssh/sshd_config
               systemctl restart ssh
               echo -e "${GREEN}SSH port changed to $port${NC}"
           else
               echo -e "${RED}Invalid port number${NC}"
           fi
           ;;
        2) read -p "Enter new Dropbear port: " port
           if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
               sed -i "s/^DROPBEAR_PORT=.*/DROPBEAR_PORT=$port/" /etc/default/dropbear
               systemctl restart dropbear
               echo -e "${GREEN}Dropbear port changed to $port${NC}"
           else
               echo -e "${RED}Invalid port number${NC}"
           fi
           ;;
        3) read -p "Enter new SSL port: " port
           if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
               sed -i "s/^accept = .*/accept = $port/" /etc/stunnel/stunnel.conf
               systemctl restart stunnel4
               echo -e "${GREEN}SSL port changed to $port${NC}"
           else
               echo -e "${RED}Invalid port number${NC}"
           fi
           ;;
        4) read -p "Enter new WebSocket port: " port
           if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
               find /usr/local/bin/ -name 'ws-*' -type f -exec sed -i "s/^LISTENING_PORT=.*/LISTENING_PORT=$port/" {} \;
               systemctl restart ws-dropbear
               echo -e "${GREEN}WebSocket port changed to $port${NC}"
           else
               echo -e "${RED}Invalid port number${NC}"
           fi
           ;;
        0) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Backup configuration function
backup_config() {
    backup_dir="/root/vpn_backup"
    backup_file="vpn_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    mkdir -p "$backup_dir"
    
    echo -e "\n${YELLOW}Creating backup...${NC}"
    tar -czf "$backup_dir/$backup_file" \
        /etc/ssh/sshd_config \
        /etc/default/dropbear \
        /etc/stunnel/stunnel.conf \
        /usr/local/bin/ws-* \
        2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Backup created: $backup_dir/$backup_file${NC}"
        echo -e "Backup size: $(du -h "$backup_dir/$backup_file" | cut -f1)"
    else
        echo -e "${RED}Backup failed!${NC}"
    fi
}

# Restore configuration function
restore_config() {
    backup_dir="/root/vpn_backup"
    
    if [ ! -d "$backup_dir" ]; then
        echo -e "${RED}No backup directory found!${NC}"
        return 1
    fi
    
    echo -e "\n${YELLOW}Available backups:${NC}"
    backups=($(ls -1 "$backup_dir"/*.tar.gz 2>/dev/null))
    
    if [ ${#backups[@]} -eq 0 ]; then
        echo -e "${RED}No backup files found!${NC}"
        return 1
    fi
    
    for i in "${!backups[@]}"; do
        echo "$((i+1)). $(basename "${backups[$i]}") ($(du -h "${backups[$i]}" | cut -f1))"
    done
    
    read -p "Enter backup number to restore [1-${#backups[@]}]: " choice
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#backups[@]} ]; then
        backup_file="${backups[$((choice-1))]}"
        
        echo -e "${YELLOW}Restoring backup...${NC}"
        tar -xzf "$backup_file" -C / 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Configuration restored successfully!${NC}"
            read -p "Do you want to restart services? [Y/n] " restart
            if [[ "$restart" =~ ^[Yy]$ ]] || [ -z "$restart" ]; then
                restart_services
            fi
        else
            echo -e "${RED}Restore failed!${NC}"
        fi
    else
        echo -e "${RED}Invalid selection!${NC}"
    fi
}

# Update script function
update_script() {
    echo -e "\n${YELLOW}Checking for updates...${NC}"
    
    # Backup current script
    cp "$0" "$0.bak"
    
    if wget -q -O "$0.tmp" "https://raw.githubusercontent.com/Defebs-vpn/nubz/main/menu.sh"; then
        if diff "$0" "$0.tmp" >/dev/null; then
            echo -e "${GREEN}Script is already up to date!${NC}"
            rm "$0.tmp"
        else
            mv "$0.tmp" "$0"
            chmod +x "$0"
            echo -e "${GREEN}Script updated successfully!${NC}"
            echo -e "${YELLOW}Restarting script...${NC}"
            exec "$0"
        fi
    else
        echo -e "${RED}Update failed!${NC}"
        if [ -f "$0.tmp" ]; then
            rm "$0.tmp"
        fi
    fi
}

# Function to fix inactive services
fix_inactive_services() {
    echo -e "\n${YELLOW}=== FIXING INACTIVE SERVICES ===${NC}"
    
    # Fix stunnel4
    if [ "$(systemctl is-active stunnel4)" != "active" ]; then
        echo -e "\n${YELLOW}Fixing stunnel4...${NC}"
        # Check configuration
        if [ ! -f "/etc/stunnel/stunnel.conf" ]; then
            echo -e "${RED}stunnel4 configuration missing. Creating default config...${NC}"
            cat > /etc/stunnel/stunnel.conf << EOF
pid = /var/run/stunnel4.pid
cert = /etc/stunnel/stunnel.pem
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:143

[openssh]
accept = 777
connect = 127.0.0.1:22
EOF
        fi
        
        # Check certificate
        if [ ! -f "/etc/stunnel/stunnel.pem" ]; then
            echo -e "${YELLOW}Generating self-signed certificate...${NC}"
            openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
                -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=Defebs-vpn" \
                -keyout /etc/stunnel/stunnel.pem \
                -out /etc/stunnel/stunnel.pem
            chmod 600 /etc/stunnel/stunnel.pem
        fi
        
        systemctl enable stunnel4
        systemctl restart stunnel4
    fi

    # Fix ws-dropbear
    if [ "$(systemctl is-active ws-dropbear)" != "active" ]; then
        echo -e "\n${YELLOW}Fixing ws-dropbear...${NC}"
        # Check if binary exists
        if [ ! -f "/usr/local/bin/ws-dropbear" ]; then
            echo -e "${YELLOW}Downloading ws-dropbear...${NC}"
            wget -O /usr/local/bin/ws-dropbear "https://raw.githubusercontent.com/Defebs-vpn/nubz/main/files/ws-dropbear"
            chmod +x /usr/local/bin/ws-dropbear
        fi
        
        # Create service file if missing
        if [ ! -f "/etc/systemd/system/ws-dropbear.service" ]; then
            cat > /etc/systemd/system/ws-dropbear.service << EOF
[Unit]
Description=Websocket-Dropbear By Defebs-vpn
Documentation=https://github.com/Defebs-vpn/nubz
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
ExecStart=/usr/local/bin/ws-dropbear -f /usr/local/bin/ws-dropbear 80
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
        fi
        
        systemctl daemon-reload
        systemctl enable ws-dropbear
        systemctl restart ws-dropbear
    fi

    # Fix badvpn
    if [ "$(systemctl is-active badvpn)" != "active" ]; then
        echo -e "\n${YELLOW}Fixing badvpn...${NC}"
        # Check if binary exists
        if [ ! -f "/usr/bin/badvpn-udpgw" ]; then
            echo -e "${YELLOW}Downloading badvpn...${NC}"
            wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/Defebs-vpn/nubz/main/files/badvpn-udpgw64"
            chmod +x /usr/bin/badvpn-udpgw
        fi
        
        # Create service file if missing
        if [ ! -f "/etc/systemd/system/badvpn.service" ]; then
            cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDP Gateway By Defebs-vpn
Documentation=https://github.com/Defebs-vpn/nubz
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
        fi
        
        systemctl daemon-reload
        systemctl enable badvpn
        systemctl restart badvpn
    fi

    # Verify all services after fixes
    echo -e "\n${YELLOW}Verifying services status...${NC}"
    services=("ssh" "dropbear" "stunnel4" "ws-dropbear" "badvpn")
    
    printf "%-20s %-15s %-20s\n" "Service" "Status" "Port"
    echo -e "------------------------------------------------------------"
    
    for service in "${services[@]}"; do
        status=$(systemctl is-active "$service")
        port=""
        
        case $service in
            "ssh") port="22" ;;
            "dropbear") port="143" ;;
            "stunnel4") port="443" ;;
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

echo -e "\n${YELLOW}Service recovery completed. Please check the status above.${NC}"
echo -e "${BLUE}If any services are still inactive, please check the logs using:${NC}"
echo -e "journalctl -u service-name"
echo -e "\nPress Enter to continue..."
read

# Main script execution
check_root
check_requirements

while true; do
    show_banner
    show_menu
    
    case $choice in
        1)  create_user ;;
        2)  delete_user ;;
        3)  view_users ;;
        4)  monitor_login ;;
        5)  check_services ;;
        6)  restart_services ;;
        7)  fix_inactive_services ;;
        8)  change_port ;;
        9)  speed_test ;;
        10) system_info ;;
        11) bandwidth_monitor ;;
        12) backup_config ;;
        13) restore_config ;;
        14) update_script ;;
        0)  clear
            echo -e "${BLUE}================================================================${NC}"
            echo -e "${GREEN}                Thank you for using VPN Manager!               ${NC}"
            echo -e "${BLUE}================================================================${NC}"
            echo -e "${YELLOW}                        Exiting...                            ${NC}"
            sleep 2
            clear
            exit 0 
            ;;
        *)  echo -e "${RED}Error: Invalid option${NC}" ;;
    esac
    
    echo -e "\nPress Enter to return to main menu..."
    read
done
