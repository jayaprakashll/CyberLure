import os
import json
import time
import threading
import requests
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from splunklib.client import connect
from splunklib.modularinput import Event

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
LOG_DIR = "../logs/"
COWRIE_LOG = os.path.join(LOG_DIR, "cowrie/cowrie.log")
DIONAEA_LOG = os.path.join(LOG_DIR, "dionaea/dionaea.log")
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
SPLUNK_CONFIG = {
    "host": "localhost",
    "port": 8089,
    "username": "admin",
    "password": "yourpassword"
}
TELEGRAM_CONFIG = {
    "bot_token": "your_telegram_bot_token",
    "chat_id": "your_chat_id"
}
EMAIL_CONFIG = {
    "enabled": True,
    "smtp_server": "smtp.gmail.com",
    "port": 587,
    "username": "your_email@gmail.com",
    "password": "your_email_password",
    "recipient": "alert_recipient@gmail.com"
}

# Threat Intelligence - IP Reputation Check
def check_ip_reputation(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {}).get("abuseConfidenceScore", 0) > 50
    except requests.RequestException as e:
        logging.error(f"IP reputation check failed: {e}")
    return False

# Alert via Email
def send_email_alert(subject, message):
    if not EMAIL_CONFIG["enabled"]:
        return
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_CONFIG["username"]
        msg["To"] = EMAIL_CONFIG["recipient"]
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))
        server = smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["port"])
        server.starttls()
        server.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
        server.sendmail(EMAIL_CONFIG["username"], EMAIL_CONFIG["recipient"], msg.as_string())
        server.quit()
        logging.info("Email alert sent successfully")
    except Exception as e:
        logging.error(f"Email alert failed: {e}")

# Alert via Telegram
def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_CONFIG['bot_token']}/sendMessage"
    payload = {"chat_id": TELEGRAM_CONFIG['chat_id'], "text": message}
    try:
        requests.post(url, json=payload, timeout=5)
        logging.info("Telegram alert sent successfully")
    except requests.RequestException as e:
        logging.error(f"Telegram alert failed: {e}")

# Splunk Integration
def log_to_splunk(event_data):
    try:
        service = connect(**SPLUNK_CONFIG)
        event = Event()
        event.stanza = "honeypot_alerts"
        event.data = json.dumps(event_data)
        service.indexes["main"].submit(event)
        logging.info("Logged event to Splunk successfully")
    except Exception as e:
        logging.error(f"Splunk logging failed: {e}")

# Log Monitoring with Performance Optimization
def monitor_log(log_file, alert_function):
    seen_entries = set()
    with open(log_file, "r") as f:
        f.seek(0, os.SEEK_END)
    while True:
        try:
            with open(log_file, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    if line not in seen_entries:
                        seen_entries.add(line)
                        alert_function(line)
        except FileNotFoundError:
            logging.error(f"{log_file} not found.")
        time.sleep(5)

# Honeypot Alert Handlers
def honeypot_alert_handler(log_line, honeypot_type):
    try:
        log_data = json.loads(log_line)
        attacker_ip = log_data.get("src_ip" if honeypot_type == "Cowrie" else "remote_host", "Unknown")
        if check_ip_reputation(attacker_ip):
            alert_message = f"[ALERT] {honeypot_type} attack detected from {attacker_ip}"
            send_email_alert(f"{honeypot_type} Honeypot Alert", alert_message)
            send_telegram_alert(alert_message)
            log_to_splunk({"source": honeypot_type, "ip": attacker_ip, "alert": "Intrusion detected"})
    except json.JSONDecodeError:
        pass

# Multi-threaded Monitoring
def start_monitoring():
    cowrie_thread = threading.Thread(target=monitor_log, args=(COWRIE_LOG, lambda log: honeypot_alert_handler(log, "Cowrie")))
    dionaea_thread = threading.Thread(target=monitor_log, args=(DIONAEA_LOG, lambda log: honeypot_alert_handler(log, "Dionaea")))
    cowrie_thread.start()
    dionaea_thread.start()
    cowrie_thread.join()
    dionaea_thread.join()

if __name__ == "__main__":
    logging.info("Starting CyberLure Alert System...")
    start_monitoring()

