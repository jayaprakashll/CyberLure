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
THREAT_INTEL_API = "https://threat-intel-api.example.com/check"
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

def check_ip_threat_level(ip):
    params = {"ip": ip, "key": ABUSEIPDB_API_KEY}
    try:
        response = requests.get(THREAT_INTEL_API, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("threat_score", 0) > 50
    except requests.RequestException as e:
        logging.error(f"Threat Intelligence API failed: {e}")
    return False

def send_alert(subject, message):
    send_email_alert(subject, message)
    send_telegram_alert(message)
    log_to_splunk({"subject": subject, "message": message})

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

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_CONFIG['bot_token']}/sendMessage"
    payload = {"chat_id": TELEGRAM_CONFIG['chat_id'], "text": message}
    try:
        requests.post(url, json=payload, timeout=5)
        logging.info("Telegram alert sent successfully")
    except requests.RequestException as e:
        logging.error(f"Telegram alert failed: {e}")

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

def monitor_log(log_file, honeypot_type):
    seen_entries = set()
    try:
        with open(log_file, "r") as f:
            f.seek(0, os.SEEK_END)
    except FileNotFoundError:
        logging.error(f"{log_file} not found.")
        return
    while True:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    if line not in seen_entries:
                        seen_entries.add(line)
                        honeypot_alert_handler(line, honeypot_type)
        except FileNotFoundError:
            logging.error(f"{log_file} not found.")
        time.sleep(5)

def honeypot_alert_handler(log_line, honeypot_type):
    try:
        log_data = json.loads(log_line)
        attacker_ip = log_data.get("src_ip" if honeypot_type == "Cowrie" else "remote_host", "Unknown")
        if check_ip_threat_level(attacker_ip):
            alert_message = f"[ALERT] {honeypot_type} attack detected from {attacker_ip}"
            send_alert(f"{honeypot_type} Honeypot Alert", alert_message)
    except json.JSONDecodeError:
        pass

def start_monitoring():
    cowrie_thread = threading.Thread(target=monitor_log, args=(COWRIE_LOG, "Cowrie"))
    dionaea_thread = threading.Thread(target=monitor_log, args=(DIONAEA_LOG, "Dionaea"))
    cowrie_thread.start()
    dionaea_thread.start()
    cowrie_thread.join()
    dionaea_thread.join()

if __name__ == "__main__":
    logging.info("Starting CyberLure Threat Intelligence System...")
    start_monitoring()

