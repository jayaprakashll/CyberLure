
#!/bin/bash

# CyberLure Signature Update Script
# Author: CyberKid
# Version: 2.0
# Features:
# - Updates Cowrie, Dionaea, and Suricata signatures
# - Checks internet connectivity before updating
# - Backs up existing signature files before modification
# - Logs update process for tracking
# - Uses version control (Git) to track changes

set -e  # Exit on error
set -o pipefail  # Ensure piped commands fail properly

# Colors for output
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

# Directories
COWRIE_DIR="/opt/cowrie"
DIONAEA_DIR="/opt/dionaea"
SURICATA_DIR="/etc/suricata"
LOG_FILE="/var/log/cyberlure_signature_update.log"
BACKUP_DIR="/var/backups/cyberlure"

# Functions
log_info() { echo -e "${GREEN}[INFO] $1${RESET}" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARNING] $1${RESET}" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR] $1${RESET}" | tee -a "$LOG_FILE"; exit 1; }

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root!"
fi

# Check internet connectivity
log_info "Checking internet connectivity..."
ping -c 3 google.com > /dev/null 2>&1 || log_error "No internet connection. Exiting."

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to backup files
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file")_$(date +%F_%T).bak"
        log_info "Backup created for $file"
    fi
}

# Update Cowrie Signatures
log_info "Updating Cowrie signatures..."
cd "$COWRIE_DIR"
backup_file "cowrie.cfg"
git pull origin master || log_warn "Cowrie update failed! Using existing signatures."
systemctl restart cowrie

# Update Dionaea Signatures
log_info "Updating Dionaea malware signatures..."
cd "$DIONAEA_DIR"
backup_file "dionaea.conf"
git pull origin master || log_warn "Dionaea update failed! Using existing signatures."
systemctl restart dionaea

# Update Suricata Rules (If Installed)
if command -v suricata > /dev/null 2>&1; then
    log_info "Updating Suricata IDS signatures..."
    backup_file "$SURICATA_DIR/rules/suricata.rules"
    suricata-update || log_warn "Suricata update failed!"
    systemctl restart suricata
else
    log_warn "Suricata not installed. Skipping update."
fi

# Log the update timestamp
log_info "Signature update completed successfully on $(date)"

exit 0
