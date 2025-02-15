#!/bin/bash
# ==================================================================
# Multi Protocol VPN Tunneling Script
# Created by: Defebs-vpn
# Created at: 2025-02-14 21:52:31 UTC
# Version: 2.3.0
# Repository: https://github.com/Defebs-vpn/nubz
# ==================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
NC='\033[0m'

# Script Information
SCRIPT_VERSION="2.3.0"
SCRIPT_CREATED="2025-02-14 21:52:31 UTC"
SCRIPT_CREATOR="SI KONTOL"

# Default Configuration
SSH_PORT=22
SSL_PORT=443
WS_PORT=80
OVPN_PORT=1194
VMESS_PORT=8880
VLESS_PORT=2083
TROJAN_PORT=2087
UDP_PORT=7300

# System Information
MYIP=$(wget -qO- ipv4.icanhazip.com)
HOSTNAME=$(hostname)
OS_NAME=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME=//g' | sed 's/"//g')
OS_VERSION=$(cat /etc/os-release | grep -w VERSION_ID | head -n1 | sed 's/VERSION_ID=//g' | sed 's/"//g')
ARCH=$(uname -m)
KERNEL=$(uname -r)

# Installation Path
INSTALL_DIR="/usr/local/nubz"
INSTALL_LOG="/var/log/vpn_setup.log"
BACKUP_DIR="/root/vpn_backup"

# Function: Show Script Banner
show_banner() {
    clear
    echo -e "${BLUE}================================================================${NC}"
    echo -e "$PURPLE  ____  _____ _____ _____ ____  ____      __     ______  _   _ $NC"
    echo -e "$PURPLE |  _ \|  ___|  ___| ____|  _ \/ ___|    \ \   / /  _ \| \ | |$NC"
    echo -e "$PURPLE | | | | |_  | |_  |  _| | |_) \___ \     \ \ / /| |_) |  \| |$NC"
    echo -e "$PURPLE | |_| |  _| |  _| | |___|  _ < ___) |     \ V / |  __/| |\  |$NC"
    echo -e "$PURPLE |____/|_|   |_|   |_____|_| \_\____/       \_/  |_|   |_| \_|$NC"
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${YELLOW}             MULTI PROTOCOL VPN TUNNEL INSTALLER${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${CYAN}» Created by   : $SCRIPT_CREATOR"
    echo -e "» Created at   : $SCRIPT_CREATED"
    echo -e "» Version      : $SCRIPT_VERSION${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${GREEN}                    SYSTEM INFORMATION${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${CYAN}» Hostname     : $HOSTNAME"
    echo -e "» IP Address   : $MYIP"
    echo -e "» OS Name      : $OS_NAME"
    echo -e "» OS Version   : $OS_VERSION"
    echo -e "» Architecture : $ARCH"
    echo -e "» Kernel       : $KERNEL${NC}"
    echo -e "${BLUE}================================================================${NC}"
}

# Cloudflare Configuration
CF_ZONE_ID="5dae12d8f2f47182f90978e42b52522a"
CF_API_TOKEN="EGVs2f1gfy7AVGE-3pXunVxhWhSyQWIkdfztY_pV"
CF_EMAIL="dedefebriansyah402@gmail.com"
DOMAIN="defebs-vpn.my.id"

# Function: Initialize Installation
init_installation() {
    echo -e "\n${YELLOW}Initializing Installation...${NC}"
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$BACKUP_DIR"
    touch "$INSTALL_LOG"
    
    # Set timezone
    timedatectl set-timezone Asia/Jakarta
    
    # Update package list
    echo -e "${YELLOW}Updating system packages...${NC}"
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    
    # Install jq first for JSON processing
    echo -e "${YELLOW}Installing jq...${NC}"
    apt install -y jq || {
        echo -e "${RED}Failed to install jq. Retrying with alternative method...${NC}"
        apt-get update
        apt-get install -y jq
    }
    
    # Verify jq installation
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}Failed to install jq. Installing manually...${NC}"
        wget -O /usr/bin/jq "https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64"
        chmod +x /usr/bin/jq
    fi
    
    # Install required packages
    echo -e "${YELLOW}Installing required packages...${NC}"
    apt install -y \
        curl \
        wget \
        git \
        zip \
        unzip \
        tar \
        build-essential \
        cmake \
        make \
        gcc \
        g++ \
        netfilter-persistent \
        iptables-persistent \
        net-tools \
        bc \
        vnstat \
        python \
        python3 \
        python-pip \
        python3-pip \
        nginx \
        certbot \
        python3-certbot-nginx \
        openssh-server \
        dropbear \
        stunnel4 \
        fail2ban \
        ufw \
        needrestart \
        ca-certificates \
        openssl \
        cron \
        pwgen \
        nscd \
        libxml-parser-perl \
        squid \
        neofetch \
        htop \
        mlocate \
        dnsutils \
        libsqlite3-dev \
        socat \
        bash-completion \
        ntpdate \
        apache2-utils \
        sysstat \
        || {
            echo -e "${RED}Failed to install some packages. Retrying...${NC}"
            apt-get update
            apt-get install -y curl wget git zip unzip tar build-essential cmake make gcc g++ \
            netfilter-persistent iptables-persistent net-tools jq bc vnstat python python3 \
            python-pip python3-pip nginx certbot python3-certbot-nginx openssh-server dropbear \
            stunnel4 fail2ban ufw needrestart ca-certificates openssl cron pwgen nscd \
            libxml-parser-perl squid neofetch htop mlocate dnsutils libsqlite3-dev socat \
            bash-completion ntpdate apache2-utils sysstat
        }
        
    # Clear package cache
    apt clean
    apt autoremove -y
    
    echo -e "${GREEN}Initialization completed successfully!${NC}"
}

# Function: Configure Domain and DNS
setup_domain() {
    clear
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${YELLOW}                  DOMAIN CONFIGURATION SETUP${NC}"
    echo -e "${BLUE}================================================================${NC}"
    
    # Get Domain Information
    echo -ne "\n${CYAN}Enter your domain name (e.g., example.com): ${NC}"
    read domain_name
    
    echo -ne "${CYAN}Enter subdomain prefix (e.g., vpn for vpn.example.com): ${NC}"
    read sub_prefix
    
    echo -ne "${CYAN}Enter Cloudflare Zone ID: ${NC}"
    read zone_id
    
    echo -ne "${CYAN}Enter Cloudflare API Token: ${NC}"
    read api_token
    
    echo -ne "${CYAN}Enter Cloudflare Email: ${NC}"
    read cf_email
    
    # Validate Input
    if [[ -z "$domain_name" || -z "$sub_prefix" || -z "$zone_id" || -z "$api_token" || -z "$cf_email" ]]; then
        echo -e "${RED}Error: All fields are required!${NC}"
        return 1
    fi
    
    # Set Global Variables
    DOMAIN="$domain_name"
    SUB_DOMAIN="${sub_prefix}"
    CF_ZONE_ID="$zone_id"
    CF_API_TOKEN="$api_token"
    CF_EMAIL="$cf_email"

    # Update DNS Record
    update_dns_record
}

# Function: Update DNS Record in Cloudflare
# Update the DNS record function to handle existing records better:
update_dns_record() {
    echo -e "\n${YELLOW}Checking DNS Records...${NC}"
    
    # First, list all DNS records to find existing ones
    LIST_RECORDS=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
     -H "Authorization: Bearer ${CF_API_TOKEN}" \
     -H "Content-Type: application/json")

    # Check if the subdomain already exists
    EXISTING_RECORD=$(echo "$LIST_RECORDS" | jq -r '.result[] | select(.name=="'"${SUB_DOMAIN}"'")')
    
    if [[ ! -z "$EXISTING_RECORD" ]]; then
        echo -e "${YELLOW}Found existing DNS record for ${SUB_DOMAIN}${NC}"
        RECORD_ID=$(echo "$EXISTING_RECORD" | jq -r '.id')
        CURRENT_IP=$(echo "$EXISTING_RECORD" | jq -r '.content')
        
        if [[ "$CURRENT_IP" == "$MYIP" ]]; then
            echo -e "${GREEN}DNS record already points to current IP ($MYIP)${NC}"
        else
            echo -e "${YELLOW}Updating DNS record from $CURRENT_IP to $MYIP${NC}"
            
            UPDATE_RECORD=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
             -H "Authorization: Bearer ${CF_API_TOKEN}" \
             -H "Content-Type: application/json" \
             --data '{
               "type": "A",
               "name": "'${SUB_DOMAIN}'",
               "content": "'${MYIP}'",
               "ttl": 120,
               "proxied": false
             }')
            
            if [[ $(echo "$UPDATE_RECORD" | jq -r '.success') == "true" ]]; then
                echo -e "${GREEN}Successfully updated DNS record to new IP${NC}"
            else
                error_msg=$(echo "$UPDATE_RECORD" | jq -r '.errors[0].message')
                echo -e "${RED}Failed to update DNS record! Error: ${error_msg}${NC}"
                return 1
            fi
        fi
    else
        echo -e "${YELLOW}Creating new DNS record for ${SUB_DOMAIN}${NC}"
        
        CREATE_RECORD=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
         -H "Authorization: Bearer ${CF_API_TOKEN}" \
         -H "Content-Type: application/json" \
         --data '{
           "type": "A",
           "name": "'${SUB_DOMAIN}'",
           "content": "'${MYIP}'",
           "ttl": 120,
           "proxied": false
         }')
        
        if [[ $(echo "$CREATE_RECORD" | jq -r '.success') == "true" ]]; then
            echo -e "${GREEN}Successfully created new DNS record${NC}"
        else
            error_msg=$(echo "$CREATE_RECORD" | jq -r '.errors[0].message')
            echo -e "${RED}Failed to create DNS record! Error: ${error_msg}${NC}"
            return 1
        fi
    fi
    
    # Verify DNS propagation
    echo -e "\n${YELLOW}Verifying DNS propagation...${NC}"
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo -e "${YELLOW}Attempt $attempt of $max_attempts${NC}"
        
        if nslookup "$SUB_DOMAIN" | grep -q "$MYIP"; then
            echo -e "${GREEN}DNS has been propagated successfully!${NC}"
            echo -e "${GREEN}DNS record for ${SUB_DOMAIN} points to ${MYIP}${NC}"
            return 0
        else
            if [ $attempt -eq $max_attempts ]; then
                echo -e "${YELLOW}DNS propagation taking longer than expected...${NC}"
                echo -e "${YELLOW}Continuing with installation. DNS may take up to 24 hours to fully propagate.${NC}"
                return 0
            fi
            echo -e "${YELLOW}DNS is still propagating... waiting 30 seconds${NC}"
            sleep 30
            ((attempt++))
        fi
    done
}

# Function: Setup SSH
setup_ssh() {
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Configure SSH
    cat > /etc/ssh/sshd_config << EOF
Port $SSH_PORT
PermitRootLogin yes
PasswordAuthentication yes
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
Banner /etc/issue.net
EOF

    # Create SSH Banner
    cat > /etc/issue.net << EOF
<b>★★★ PREMIUM VPN SERVER ★★★</b>
<b>⚠ NO SPAM !!!</b>
<b>⚠ NO DDOS !!!</b>
<b>⚠ NO HACKING !!!</b>
<b>⚠ NO CARDING !!!</b>
<b>⚠ NO CRIMINAL CYBER !!!</b>
<b>⚠ NO ABUSE !!!</b>
<b>★ Thanks for Using Our Service ★</b>
EOF

    # Restart SSH Service
    systemctl restart ssh
}

# Function: Setup Dropbear
setup_dropbear() {
    # Backup original config
    cp /etc/default/dropbear /etc/default/dropbear.bak
    
    # Configure Dropbear
    cat > /etc/default/dropbear << EOF
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 50000"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
EOF

    # Restart Dropbear Service
    systemctl restart dropbear
}

# Function: Setup SSL Certificate with Let's Encrypt
setup_ssl_cert() {
    echo -e "\n${YELLOW}Setting up SSL Certificate...${NC}"
    
    # Install certbot if not installed
    if ! command -v certbot &> /dev/null; then
        apt-get install -y certbot python3-certbot-nginx
    fi
    
    # Stop nginx if running
    systemctl stop nginx
    
    # Get SSL Certificate
    certbot certonly --standalone --preferred-challenges http \
        --agree-tos --email "${CF_EMAIL}" -d "${SUB_DOMAIN}" \
        --non-interactive
    
    # Check if certificate was obtained
    if [[ -f "/etc/letsencrypt/live/${SUB_DOMAIN}/fullchain.pem" ]]; then
        echo -e "${GREEN}SSL Certificate obtained successfully!${NC}"
        
        # Configure stunnel with Let's Encrypt certificate
        cat > /etc/stunnel/stunnel.conf << EOF
pid = /var/run/stunnel4.pid
cert = /etc/letsencrypt/live/${SUB_DOMAIN}/fullchain.pem
key = /etc/letsencrypt/live/${SUB_DOMAIN}/privkey.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = $SSL_PORT
connect = 127.0.0.1:143

[openssh]
accept = 777
connect = 127.0.0.1:$SSH_PORT

[openvpn]
accept = 442
connect = 127.0.0.1:$OVPN_PORT

[vmess]
accept = 443
connect = 127.0.0.1:$VMESS_PORT

[vless]
accept = 443
connect = 127.0.0.1:$VLESS_PORT

[trojan]
accept = 443
connect = 127.0.0.1:$TROJAN_PORT
EOF
        
        # Setup auto-renewal
        cat > /etc/cron.daily/cert-renewal << EOF
#!/bin/bash
certbot renew --quiet --no-self-upgrade --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx && systemctl restart stunnel4"
EOF
        chmod +x /etc/cron.daily/cert-renewal
        
        # Restart stunnel
        systemctl restart stunnel4
    else
        echo -e "${RED}Failed to obtain SSL Certificate! Using self-signed certificate instead.${NC}"
        
        # Generate self-signed certificate
        openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
            -subj "/C=ID/ST=Jakarta/L=Jakarta/O=${SCRIPT_CREATOR}/OU=VPN Premium/CN=${SUB_DOMAIN}" \
            -keyout /etc/stunnel/stunnel.pem \
            -out /etc/stunnel/stunnel.pem
            
        # Configure stunnel with self-signed certificate
        cat > /etc/stunnel/stunnel.conf << EOF
pid = /var/run/stunnel4.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = $SSL_PORT
connect = 127.0.0.1:143

[openssh]
accept = 777
connect = 127.0.0.1:$SSH_PORT

[openvpn]
accept = 442
connect = 127.0.0.1:$OVPN_PORT

[vmess]
accept = 443
connect = 127.0.0.1:$VMESS_PORT

[vless]
accept = 443
connect = 127.0.0.1:$VLESS_PORT

[trojan]
accept = 443
connect = 127.0.0.1:$TROJAN_PORT
EOF
        
        # Restart stunnel
        systemctl restart stunnel4
    fi
}

# Function: Setup WebSocket
setup_websocket() {
    # Download WebSocket Scripts
    wget -O /usr/local/bin/ws-dropbear "https://raw.githubusercontent.com/Defebs-vpn/nubz/main/files/ws-dropbear"
    wget -O /usr/local/bin/ws-openssh "https://raw.githubusercontent.com/Defebs-vpn/nubz/main/files/ws-openssh"
    chmod +x /usr/local/bin/ws-*
    
    # Create WebSocket Services
    cat > /etc/systemd/system/ws-dropbear.service << EOF
[Unit]
Description=Websocket-Dropbear By ${SCRIPT_CREATOR}
Documentation=https://github.com/Defebs-vpn/nubz
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
ExecStart=/usr/local/bin/ws-dropbear -f /usr/local/bin/ws-dropbear $WS_PORT
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/ws-openssh.service << EOF
[Unit]
Description=Websocket-OpenSSH By ${SCRIPT_CREATOR}
Documentation=https://github.com/Defebs-vpn/nubz
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
ExecStart=/usr/local/bin/ws-openssh -f /usr/local/bin/ws-openssh $WS_PORT
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    # Start WebSocket Services
    systemctl daemon-reload
    systemctl enable ws-dropbear
    systemctl enable ws-openssh
    systemctl start ws-dropbear
    systemctl start ws-openssh
}

# Function: Setup BadVPN UDP
setup_badvpn() {
    # Download BadVPN
    wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/Defebs-vpn/nubz/main/files/badvpn-udpgw64"
    chmod +x /usr/bin/badvpn-udpgw
    
    # Create BadVPN Service
    cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDP Gateway By ${SCRIPT_CREATOR}
Documentation=https://github.com/Defebs-vpn/nubz
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:$UDP_PORT --max-clients 1000 --max-connections-for-client 10
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # Start BadVPN Service
    systemctl daemon-reload
    systemctl enable badvpn
    systemctl start badvpn
}

# Function: Setup Firewall
setup_firewall() {
    # Reset UFW
    ufw --force reset
    
    # Configure UFW
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow $SSH_PORT/tcp
    
    # Allow Dropbear
    ufw allow 143/tcp
    ufw allow 50000/tcp
    
    # Allow SSL
    ufw allow $SSL_PORT/tcp
    ufw allow 777/tcp
    
    # Allow WebSocket
    ufw allow $WS_PORT/tcp
    
    # Allow UDP
    ufw allow $UDP_PORT/udp
    
    # Allow Other Ports
    ufw allow $OVPN_PORT/tcp
    ufw allow $VMESS_PORT/tcp
    ufw allow $VLESS_PORT/tcp
    ufw allow $TROJAN_PORT/tcp
    
    # Enable UFW
    echo "y" | ufw enable
}

# Function: Setup Fail2Ban
setup_fail2ban() {
    # Configure Fail2Ban
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = 127.0.0.1
findtime = 600
bantime = 3600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[dropbear]
enabled = true
port = 143,50000
filter = dropbear
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600
EOF

    # Restart Fail2Ban
    systemctl restart fail2ban
}

# Function: Install Management Scripts
install_scripts() {
    # Download Scripts
    wget -O /usr/local/bin/menu "https://raw.githubusercontent.com/Defebs-vpn/nubz/main/menu.sh"
    wget -O /usr/local/bin/monitor "https://raw.githubusercontent.com/Defebs-vpn/nubz/main/monitor.sh"
    
    # Set Permissions
    chmod +x /usr/local/bin/menu
    chmod +x /usr/local/bin/monitor
    
    # Create Aliases
    echo "alias menu='/usr/local/bin/menu'" >> /root/.bashrc
    echo "alias monitor='/usr/local/bin/monitor'" >> /root/.bashrc
}

# Function: Final Configuration
final_config() {
    # Set Timezone
    timedatectl set-timezone Asia/Jakarta
    
    # Enable IPv4 Forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    
    # Optimize System
    cat > /etc/security/limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF

    # Setup Cron for Auto Cleanup
    cat > /etc/cron.daily/cleanup_vpn << EOF
#!/bin/bash
# Daily cleanup script
find /tmp -type f -exec rm -f {} \;
truncate -s 0 /var/log/*.log
service rsyslog restart
EOF
    chmod +x /etc/cron.daily/cleanup_vpn
    
    # Update RC Local
    cat > /etc/rc.local << EOF
#!/bin/bash
# RC Local Script
iptables-restore < /etc/iptables.rules
ip6tables-restore < /etc/ip6tables.rules
systemctl restart ssh
systemctl restart dropbear
systemctl restart stunnel4
systemctl restart ws-dropbear
systemctl restart ws-openssh
systemctl restart badvpn
exit 0
EOF
    chmod +x /etc/rc.local
}

# Update create_info function to include domain information
# Function: Create Installation Info
create_info() {
    cat > $INSTALL_DIR/installation.info << EOF
====================================================================
                       VPN SERVER INFORMATION
====================================================================
Created by : $SCRIPT_CREATOR
Created at : $SCRIPT_CREATED
Version    : $SCRIPT_VERSION

» Server Information
-------------------
Hostname   : $HOSTNAME
IP Address : $MYIP
OS         : $OS_NAME
Version    : $OS_VERSION
Arch       : $ARCH
Kernel     : $KERNEL

» Port Configuration
-------------------
SSH        : $SSH_PORT
Dropbear   : 143, 50000
SSL/TLS    : $SSL_PORT, 777
WebSocket  : $WS_PORT
OpenVPN    : $OVPN_PORT
VMESS      : $VMESS_PORT
VLESS      : $VLESS_PORT
Trojan     : $TROJAN_PORT
UDP        : $UDP_PORT

» Installation Path
------------------
Install Directory : $INSTALL_DIR
Log File         : $INSTALL_LOG
Backup Directory : $BACKUP_DIR

» Service Status
---------------
$(systemctl is-active ssh) : SSH
$(systemctl is-active dropbear) : Dropbear
$(systemctl is-active stunnel4) : Stunnel4
$(systemctl is-active ws-dropbear) : WebSocket-Dropbear
$(systemctl is-active ws-openssh) : WebSocket-OpenSSH
$(systemctl is-active badvpn) : BadVPN-UDP
$(systemctl is-active fail2ban) : Fail2Ban
$(systemctl is-active ufw) : UFW Firewall

» Domain Configuration
--------------------
Domain     : $DOMAIN
Subdomain  : $SUB_DOMAIN
SSL Status : $(if [[ -f "/etc/letsencrypt/live/${SUB_DOMAIN}/fullchain.pem" ]]; then echo "Active"; else echo "Not Configured"; fi)

» Management Commands
-------------------
menu     : Show VPN management menu
monitor  : Show server monitoring dashboard

====================================================================
            INSTALLATION COMPLETED SUCCESSFULLY
====================================================================
EOF

    # Copy to root directory for easy access
    cp $INSTALL_DIR/installation.info /root/vpn-info.txt
}

# Start Installation
main_install

# Update main_install function
main_install() {
    # Show Banner
    show_banner
    
    # Check Root Access
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
    
    # Setup Domain and DNS
    setup_domain || exit 1
    
    # Initialize Installation
    init_installation
    
    # Setup Services
    setup_ssh
    setup_dropbear
    setup_ssl_cert || echo -e "${RED}SSL Certificate setup failed, continuing with self-signed cert${NC}"
    setup_stunnel
    setup_websocket
    setup_badvpn
    setup_firewall
    setup_fail2ban
    
    # Install Management Scripts
    install_scripts
    
    # Final Configuration
    final_config
    
    # Create Installation Info
    create_info
    
    # Complete Installation
    echo -e "\n${GREEN}Installation Completed Successfully!${NC}"
    echo -e "\n${YELLOW}System will reboot in 10 seconds...${NC}"
    
    # Save iptables rules
    iptables-save > /etc/iptables.rules
    ip6tables-save > /etc/ip6tables.rules
    
    # Schedule reboot
    sleep 10 && reboot &
}

# Start Installation
main_install
