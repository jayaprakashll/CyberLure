
#!/bin/bash

# CyberLure Honeypot Logs Backup Script
# Author: CyberKid
# Version: 2.0
# Features: 
# - Compresses logs before backup
# - Encrypts backups for security
# - Supports remote storage (SFTP/Cloud)
# - Automates cleanup of old backups
# - Generates integrity checksum

# Configuration
LOG_DIR="/var/log/cyberlure"
BACKUP_DIR="/var/backups/cyberlure"
REMOTE_USER="backupuser"
REMOTE_HOST="backup.server.com"
REMOTE_DIR="/home/backupuser/honeypot_logs"
RETENTION_DAYS=7
ENCRYPTION_KEY="supersecurekey123"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Define backup file name
BACKUP_FILE="$BACKUP_DIR/honeypot_logs_$TIMESTAMP.tar.gz"

# Compress logs
tar -czf "$BACKUP_FILE" "$LOG_DIR"

# Encrypt backup (AES-256)
openssl enc -aes-256-cbc -salt -in "$BACKUP_FILE" -out "$BACKUP_FILE.enc" -pass pass:"$ENCRYPTION_KEY"

# Generate checksum
sha256sum "$BACKUP_FILE.enc" > "$BACKUP_FILE.enc.sha256"

# Securely transfer backup to remote server (SFTP)
scp "$BACKUP_FILE.enc" "$BACKUP_FILE.enc.sha256" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR"

if [ $? -eq 0 ]; then
    echo "[INFO] Backup successfully transferred to remote server."
else
    echo "[ERROR] Backup transfer failed!"
    exit 1
fi

# Cleanup local backups older than retention period
find "$BACKUP_DIR" -type f -name "honeypot_logs_*.tar.gz.enc" -mtime +$RETENTION_DAYS -exec rm -f {} \;

echo "[INFO] Backup completed successfully at $(date)"

exit 0
