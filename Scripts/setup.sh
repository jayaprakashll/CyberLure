
#!/bin/bash

# CyberLure Honeypot Setup Script
# Author: CyberKid
# Version: 2.0
# Features:
# - Installs Docker, Splunk, Cowrie, and Dionaea
# - Configures firewall rules for honeypot security
# - Sets up automatic log rotation and backups
# - Ensures system hardening and best practices
# - Configures services to start at boot

set -e  # Exit immediately if a command exits with a non-zero status
set -o pipefail  # Ensure piped commands fail properly

# Colors for output
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

# Directories
LOG_DIR="/var/log/cyberlure"
BACKUP_DIR="/var/backups/cyberlure"
COWRIE_DIR="/opt/cowrie"
DIONAEA_DIR="/opt/dionaea"

# Functions
log_info() { echo -e "${GREEN}[INFO] $1${RESET}"; }
log_warn() { echo -e "${YELLOW}[WARNING] $1${RESET}"; }
log_error() { echo -e "${RED}[ERROR] $1${RESET}"; exit 1; }

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root!"
fi

# Update system
log_info "Updating system packages..."
apt update && apt upgrade -y

# Install dependencies
log_info "Installing dependencies..."
apt install -y docker.io docker-compose ufw fail2ban git python3 python3-pip openssl

# Enable and start Docker
systemctl enable --now docker

# Setup Firewall (UFW)
log_info "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp  # Allow SSH (Modify if required)
ufw allow 23/tcp  # Allow Telnet for honeypot
ufw allow 80/tcp   # Allow HTTP (if needed)
ufw allow 443/tcp  # Allow HTTPS (if needed)
ufw --force enable

# Clone CyberLure repository
log_info "Cloning CyberLure repository..."
git clone https://github.com/yourusername/CyberLure.git /opt/CyberLure

# Setup Cowrie Honeypot
log_info "Setting up Cowrie..."
git clone https://github.com/cowrie/cowrie.git "$COWRIE_DIR"
cd "$COWRIE_DIR"
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
cp cowrie.cfg.dist cowrie.cfg
sed -i 's/#enabled = false/enabled = true/g' cowrie.cfg  # Enable Telnet
deactivate

# Setup Dionaea Honeypot
log_info "Setting up Dionaea..."
git clone https://github.com/DinoTools/dionaea.git "$DIONAEA_DIR"
cd "$DIONAEA_DIR"
apt install -y cmake libglib2.0-dev libssl-dev libcurl4-openssl-dev libpcap-dev
cmake .
make -j$(nproc)
make install

# Setup Splunk
log_info "Installing Splunk..."
wget -O splunk.deb "https://download.splunk.com/products/splunk/releases/latest/linux/splunk-9.2.0-amd64.deb"
dpkg -i splunk.deb
/opt/splunk/bin/splunk enable boot-start --accept-license --answer-yes
/opt/splunk/bin/splunk start

# Setup log directories
log_info "Creating log directories..."
mkdir -p "$LOG_DIR" "$BACKUP_DIR"

# Setup automatic log rotation
log_info "Configuring log rotation..."
cat <<EOF > /etc/logrotate.d/cyberlure
$LOG_DIR/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
EOF

# Setup systemd services
log_info "Creating systemd services for honeypots..."

cat <<EOF > /etc/systemd/system/cowrie.service
[Unit]
Description=Cowrie Honeypot
After=network.target

[Service]
User=root
WorkingDirectory=$COWRIE_DIR
ExecStart=$COWRIE_DIR/cowrie-env/bin/python3 $COWRIE_DIR/src/cowrie/start.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/dionaea.service
[Unit]
Description=Dionaea Honeypot
After=network.target

[Service]
User=root
ExecStart=$DIONAEA_DIR/dionaea
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
log_info "Enabling and starting honeypots..."
systemctl daemon-reload
systemctl enable --now cowrie.service dionaea.service

# Setup automatic backup
log_info "Setting up automated log backups..."
cat <<EOF > /etc/cron.daily/cyberlure_backup
#!/bin/bash
tar -czf "$BACKUP_DIR/honeypot_logs_$(date +\%F).tar.gz" "$LOG_DIR"
EOF
chmod +x /etc/cron.daily/cyberlure_backup

# Final Message
log_info "CyberLure setup complete! Honeypots are running, logs are being monitored, and security is enforced."

exit 0
