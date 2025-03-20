# CyberLure | Honeypot-Based Intrusion Detection System

##  Overview
CyberLure is a high-interaction honeypot designed to detect and analyze real-world cyberattacks in a controlled environment. Using **Cowrie** and **Dionaea**, it captures malicious activity, logs it for forensic analysis, and leverages **Splunk** for real-time monitoring and threat intelligence. The system enhances cybersecurity awareness by identifying brute-force attempts, malware injections, and unauthorized access.

##  Features
- **High-Interaction Honeypot**: Engages attackers using **Cowrie** (SSH/Telnet honeypot) and **Dionaea** (malware collection honeypot).
- **Real-Time Monitoring**: Logs and visualizes attack patterns with **Splunk** for network threat analysis.
- **Automated Alert System**: Triggers notifications upon detecting suspicious activities.
- **Threat Intelligence**: Tracks malicious IPs and behaviors to improve security postures.
- **Incident Response**: Provides forensic logs for in-depth cybersecurity analysis.

## System Architecture
1. **Cowrie**: Captures SSH/Telnet brute-force attempts and logs attacker interactions.
2. **Dionaea**: Identifies and stores malware samples from network interactions.
3. **Splunk**: Processes log data, provides visualization, and detects attack patterns.
4. **Automated Alerts**: Sends notifications for detected threats.
5. **Log Analysis**: Stores logs for forensic investigation and risk assessment.

##  Installation & Setup
### Prerequisites
- **Ubuntu 20.04+ / Debian-based system**
- **Python 3.x**
- **Docker & Docker Compose**
- **Splunk Free or Enterprise Edition**

### Steps to Deploy
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/CyberLure.git
   cd CyberLure
   ```
2. **Install dependencies:**
   ```bash
   sudo apt update && sudo apt install docker.io docker-compose -y
   ```
3. **Run the honeypot:**
   ```bash
   docker-compose up -d
   ```
4. **Access Splunk dashboard:**
   - Open `http://localhost:8000`
   - Login with admin credentials (set during setup)
   - Configure log sources and visualization

##  Log Analysis & Monitoring
- **Brute-force Detection**: Identify repeated login attempts on SSH/Telnet.
- **Malware Analysis**: Extract and analyze malicious binaries from Dionaea logs.
- **Attack Trends**: Track and visualize attack trends using Splunk dashboards.
- **Threat Intelligence Integration**: Cross-reference attack sources with known malicious IP databases.

##  Security & Maintenance
- Regularly update honeypot signatures.
- Restrict network access to avoid accidental exposure.
- Analyze logs periodically for evolving attack trends.
- Implement IP blocking for repeated threats.

## NOTE
In the data/malware_samples/ directory, you should store captured malware samples for analysis

##  Future Enhancements
- Integration with **ELK Stack (Elasticsearch, Logstash, Kibana)**.
- AI-based anomaly detection for advanced threat identification.
- Cloud-based log storage and analysis.

##  Contributing
Contributions are welcome! Feel free to submit issues or pull requests.

##  Acknowledgments
- [Cowrie](https://github.com/cowrie/cowrie) - SSH/Telnet Honeypot
- [Dionaea](https://github.com/DinoTools/dionaea) - Malware Collection Honeypot
- [Splunk](https://www.splunk.com/) - Security Information and Event Management (SIEM) Tool
