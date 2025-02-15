#!/bin/bash
# VPN Server Monitor
# Created by Defebs-vpn
# Created at: 2025-02-14 21:14:21

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
LOG_FILE="/var/log/vpn_monitor.log"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEM=80
ALERT_THRESHOLD_DISK=90

# Initialize log file
touch "$LOG_FILE"

# Log function
log_message() {
    echo "$(date -u '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Check CPU usage
check_cpu() {
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d. -f1)
    if [ "$cpu_usage" -gt "$ALERT_THRESHOLD_CPU" ]; then
        echo -e "${RED}WARNING: High CPU usage: ${cpu_usage}%${NC}"
        log_message "High CPU usage: ${cpu_usage}%"
    else
        echo -e "CPU Usage: ${GREEN}${cpu_usage}%${NC}"
    fi
}

# Check Memory usage
check_memory() {
    memory_usage=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
    if [ "$memory_usage" -gt "$ALERT_THRESHOLD_MEM" ]; then
        echo -e "${RED}WARNING: High Memory usage: ${memory_usage}%${NC}"
        log_message "High Memory usage: ${memory_usage}%"
    else
        echo -e "Memory Usage: ${GREEN}${memory_usage}%${NC}"
    fi
}

# Check Disk usage
check_disk() {
    disk_usage=$(df -h / | awk 'NR==2 {print $(NF-1)}' | cut -d'%' -f1)
    if [ "$disk_usage" -gt "$ALERT_THRESHOLD_DISK" ]; then
        echo -e "${RED}WARNING: High Disk usage: ${disk_usage}%${NC}"
        log_message "High Disk usage: ${disk_usage}%"
    else
        echo -e "Disk Usage: ${GREEN}${disk_usage}%${NC}"
    fi
}

# Check active connections
check_connections() {
    ssh_conn=$(netstat -anp | grep :22 | grep ESTABLISHED | wc -l)
    ws_conn=$(netstat -anp | grep :80 | grep ESTABLISHED | wc -l)
    ssl_conn=$(netstat -anp | grep :443 | grep ESTABLISHED | wc -l)
    
    echo -e "\nActive Connections:"
    echo -e "SSH: ${GREEN}${ssh_conn}${NC}"
    echo -e "WebSocket: ${GREEN}${ws_conn}${NC}"
    echo -e "SSL: ${GREEN}${ssl_conn}${NC}"
    
    log_message "Active Connections - SSH: $ssh_conn, WS: $ws_conn, SSL: $ssl_conn"
}

# Main monitoring loop
while true; do
    clear
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${GREEN}               VPN SERVER MONITOR               ${NC}"
    echo -e "${GREEN}            Created by Defebs-vpn              ${NC}"
    echo -e "${BLUE}=================================================${NC}"
    echo -e "Current Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
    echo -e "${BLUE}=================================================${NC}"
    
    check_cpu
    check_memory
    check_disk
    check_connections
    
    echo -e "\nMonitoring... (Press Ctrl+C to exit)"
    sleep 5
done