# 🛡️ Brute Force Attack Detector

> A real-time Python tool that monitors login attempts, detects brute force attacks, and automatically blocks malicious IP addresses — simulating SOC alert response workflows.

---

## 📌 About The Project

Brute force attacks are one of the most common threats to SSH and web login systems. This tool monitors authentication logs, tracks failed login attempts per IP address, and raises alerts when an IP crosses a configurable threshold.

It simulates the kind of automated detection logic used in real-world SIEM tools like Splunk and IBM QRadar — but built from scratch in Python.

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3 | Core language |
| `re` | Log pattern extraction |
| `collections` | IP-based attempt counting |
| `json` | Persistent blocked IP storage |
| `datetime` | Timestamped alerting |

---

## ✨ Features

- ✅ Real-time failed login tracking per IP
- ✅ Configurable threshold (default: 5 attempts)
- ✅ Automatic IP blocking with JSON persistence
- ✅ Separate tracking of successful vs failed logins
- ✅ Colour-coded SOC-style terminal dashboard
- ✅ Blocked IP list saved to `blocked_ips.json`
- ✅ Summary statistics panel

---

## 🚀 Getting Started

### Prerequisites
```bash
Python 3.x
```

### Installation
```bash
# Clone the repository
git clone https://github.com/Slen01/brute-force-detector.git

# Navigate to project
cd brute-force-detector
```

### Run
```bash
python brute_force_detector.py
```

---

## 📸 Sample Output

```
╔══════════════════════════════════╗
║   BRUTE FORCE ATTACK DETECTOR   ║
╚══════════════════════════════════╝

[*] SCAN SUMMARY:
  Total Log Events   : 13
  Failed Attempts    : 8
  Successful Logins  : 2
  Unique Attacker IPs: 3

[!] BRUTE FORCE ALERTS:
  ╔══ 🚨 ATTACK DETECTED ══╗
  ║  IP Address : 192.168.1.100
  ║  Attempts   : 6
  ║  Targets    : ['root', 'admin']
  ║  Status     : 🔴 BLOCKED
  ╚════════════════════════╝
```

---

## ⚙️ Configuration

```python
THRESHOLD     = 5     # Failed attempts before alert
TIME_WINDOW   = 60    # Detection window in seconds
LOG_FILE      = "sample_auth.log"
BLOCKED_IPS_FILE = "blocked_ips.json"
```

---

## 📁 Project Structure

```
brute-force-detector/
├── brute_force_detector.py   # Main detection script
├── sample_auth.log           # Auto-generated sample log
├── blocked_ips.json          # Persisted blocked IPs
└── README.md
```

---

## 🔗 Real-World Application

This tool replicates core logic found in:
- **Fail2Ban** — Linux brute force protection daemon
- **SIEM alert rules** — Splunk, QRadar, Microsoft Sentinel
- **WAF rate limiting** — Cloudflare, AWS Shield

---

## 🎯 Use Cases

- SSH brute force protection simulation
- SOC analyst training and demonstration
- Network security log analysis
- Security awareness and education

---

## 👩‍💻 Author

**Madhura Meenatchi**
- GitHub: [@Slen01](https://github.com/Slen01)
- LinkedIn: [Madhura Meenatchi](https://www.linkedin.com/in/madhura-meenatchi-anbu-326865281)
- CEH | CHFI | Cybersecurity Engineer

---

## 📜 License

MIT License — Free to use and modify with attribution.

---

> ⭐ Star this repo if it helped you understand brute force detection!
