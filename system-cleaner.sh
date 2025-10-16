#!/bin/bash

# Script: system-cleaner.sh
# Description: Automated system cleanup script for cron
# Author: System Administrator
# Run every 4 months

# Configuration
LOG_FILE="/var/log/system-cleaner.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log messages
log_message() {
    echo "[$TIMESTAMP] $1" >> "$LOG_FILE"
}

# Function to run command and log output
run_command() {
    local cmd="$1"
    local desc="$2"
    
    log_message "START: $desc"
    log_message "COMMAND: $cmd"
    
    # Execute command and capture output
    eval "$cmd" >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        log_message "SUCCESS: $desc completed"
    else
        log_message "ERROR: $desc failed with exit code $?"
    fi
    
    log_message "---"
}

# Header
log_message "=== SYSTEM CLEANUP STARTED ==="
log_message "Disk usage before cleanup:"
df -h >> "$LOG_FILE"

# Main cleanup commands
run_command "sudo apt-get autoremove --purge -y" "Remove unused packages and configs"
run_command "sudo apt-get autoclean -y" "Clean obsolete package cache"
run_command "sudo apt-get clean -y" "Clean all package cache"
run_command "dpkg -l | grep ^rc | awk '{print \$2}' | sudo xargs -r dpkg -P" "Remove residual config files"

# Additional cleanup (optional)
run_command "sudo find /var/log -type f -name '*.log' -exec truncate -s 0 {} \;" "Truncate log files"
run_command "sudo find /tmp -type f -atime +7 -delete 2>/dev/null" "Clean old temp files"

# Footer
log_message "Disk usage after cleanup:"
df -h >> "$LOG_FILE"
log_message "=== SYSTEM CLEANUP COMPLETED ==="
echo "" >> "$LOG_FILE"
