
# CyberLure Honeypot Architecture

## Overview
CyberLure is a multi-layered honeypot security system designed to detect, log, and respond to cyber threats in real-time. It integrates multiple honeypot services, including **Cowrie**, **Dionaea**, and **Splunk**, to provide comprehensive monitoring and threat intelligence.

---

## **System Components**

### **1. Honeypot Modules**
- **Cowrie (SSH/Telnet Honeypot)**  
  - Captures brute-force attacks
  - Logs attacker interactions
  - Simulates a real system to deceive attackers
- **Dionaea (Malware Capture Honeypot)**  
  - Detects malware and exploits
  - Collects binaries for analysis
  - Logs network activity

### **2. Logging & Analysis**
- **Splunk SIEM**  
  - Centralized log management
  - Custom alerting and dashboards
  - Stores and visualizes attack trends
- **Threat Intelligence API**  
  - Queries AbuseIPDB and other sources
  - Evaluates threat level of attacking IPs

### **3. Alerting Mechanisms**
- **Email Notifications** (SMTP)
- **Telegram Bot Alerts** (API)
- **Splunk Event Forwarding** (Syslog, HEC)

---

## **Architecture Diagram**
```plaintext
                     +--------------------+
                     |   Attacker         |
                     +--------------------+
                                |
        +------------------------+------------------------+
        |                        |                        |
+----------------+      +----------------+      +----------------+
|  Cowrie SSH    |      |  Dionaea HTTP  |      |  Dionaea SMB   |
|  & Telnet      |      |  & Malware     |      |  & Exploits    |
+----------------+      +----------------+      +----------------+
        |                        |                        |
        +------------------------+------------------------+
                                |
                        +----------------+
                        |    Log Parser   |
                        +----------------+
                                |
        +------------------------+------------------------+
        |                        |                        |
+----------------+      +----------------+      +----------------+
| Splunk SIEM    |      |  Alert System  |      | Threat Intel   |
| (Dashboards)   |      | (Email, Telegram) |  | (AbuseIPDB)   |
+----------------+      +----------------+      +----------------+
```

---

## **Deployment Details**
### **1. System Requirements**
- OS: Linux (Ubuntu, Arch, or CentOS)
- Dependencies: Python, Splunk, Docker (optional)
- Networking: Open ports (22, 80, 443, 445, 3306, 3389)

### **2. Installation Steps**
1. Clone the CyberLure repository:
   ```bash
   git clone https://github.com/jayaprakashll/CyberLure.git
   cd CyberLure
   ```
2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
3. Configure Splunk and Honeypots:
   - Modify `config.json` for logging settings
   - Set up Splunk with `inputs.conf`

---

## **Security Considerations**
- **Isolated Environment:** Run in a VM or container to prevent compromise.
- **Logging Encryption:** Ensure secure storage of attack logs.
- **IP Whitelisting:** Avoid exposing honeypot services to internal networks.

---

## **Conclusion**
CyberLure is a scalable and modular honeypot architecture that provides real-time attack detection, logging, and alerting. With Splunk integration and multiple honeypot types, it offers an advanced cybersecurity defense mechanism against evolving threats.


