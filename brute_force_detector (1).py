"""
==================================================
  BRUTE FORCE ATTACK DETECTOR
  Author: Your Name
  Description: Monitors login attempts in real
               time and alerts on brute force
==================================================
"""

import re
import time
import json
import os
from collections import defaultdict
from datetime import datetime

# ─── CONFIGURATION ────────────────────────────────
THRESHOLD       = 5             # Max failed attempts before alert
TIME_WINDOW     = 60            # Time window in seconds
LOG_FILE        = "sample_auth.log"
BLOCKED_IPS_FILE = "blocked_ips.json"

# ─── COLOURS ──────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def generate_sample_log():
    """Generate sample log with brute force patterns."""
    logs = [
        "Jan 10 10:01:01 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Jan 10 10:01:02 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Jan 10 10:01:03 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Jan 10 10:01:04 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Jan 10 10:01:05 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Jan 10 10:01:06 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Jan 10 10:02:00 server sshd: Accepted password for user1 from 10.0.0.5 port 22",
        "Jan 10 10:03:01 server sshd: Failed password for admin from 203.0.113.50 port 22",
        "Jan 10 10:03:02 server sshd: Failed password for admin from 203.0.113.50 port 22",
        "Jan 10 10:03:03 server sshd: Failed password for admin from 203.0.113.50 port 22",
        "Jan 10 10:03:04 server sshd: Failed password for admin from 203.0.113.50 port 22",
        "Jan 10 10:03:05 server sshd: Failed password for admin from 203.0.113.50 port 22",
        "Jan 10 10:04:00 server sshd: Accepted password for user2 from 10.0.0.8 port 22",
        "Jan 10 10:05:00 server sshd: Failed password for test from 172.16.0.99 port 22",
    ]
    with open(LOG_FILE, "w") as f:
        f.write("\n".join(logs))
    print(f"{GREEN}[+] Sample log generated: {LOG_FILE}{RESET}\n")


def load_blocked_ips():
    """Load previously blocked IPs from file."""
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_blocked_ips(blocked):
    """Save blocked IPs to file."""
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(blocked, f, indent=2)


def parse_logs(lines):
    """Parse log lines and extract failed/successful login events."""
    events = []
    failed_pattern  = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    success_pattern = re.compile(r"Accepted password for (\S+) from (\S+)")

    for line in lines:
        failed_match  = failed_pattern.search(line)
        success_match = success_pattern.search(line)

        if failed_match:
            user, ip = failed_match.groups()
            events.append({"type": "failed", "user": user, "ip": ip})

        elif success_match:
            user, ip = success_match.groups()
            events.append({"type": "success", "user": user, "ip": ip})

    return events


def detect_brute_force(events):
    """Detect IPs exceeding failed login threshold."""
    failed_counts = defaultdict(lambda: {"count": 0, "users": set()})
    alerts        = []
    blocked_ips   = load_blocked_ips()

    for event in events:
        ip   = event["ip"]
        user = event["user"]

        if event["type"] == "failed":
            failed_counts[ip]["count"] += 1
            failed_counts[ip]["users"].add(user)

            if failed_counts[ip]["count"] >= THRESHOLD:
                if ip not in blocked_ips:
                    alert = {
                        "ip"       : ip,
                        "attempts" : failed_counts[ip]["count"],
                        "targets"  : list(failed_counts[ip]["users"]),
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "status"   : "BLOCKED"
                    }
                    alerts.append(alert)
                    blocked_ips[ip] = alert

    save_blocked_ips(blocked_ips)
    return alerts, failed_counts, blocked_ips


def display_dashboard(events, alerts, failed_counts, blocked_ips):
    """Display coloured terminal dashboard."""
    print(f"\n{BOLD}{CYAN}{'=' * 60}")
    print("     BRUTE FORCE ATTACK DETECTOR - DASHBOARD")
    print(f"     Scanned at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}{RESET}\n")

    # Summary
    total_failed   = sum(1 for e in events if e["type"] == "failed")
    total_success  = sum(1 for e in events if e["type"] == "success")
    total_unique   = len(failed_counts)

    print(f"{BOLD}[*] SCAN SUMMARY:{RESET}")
    print(f"  Total Log Events   : {len(events)}")
    print(f"  Failed Attempts    : {RED}{total_failed}{RESET}")
    print(f"  Successful Logins  : {GREEN}{total_success}{RESET}")
    print(f"  Unique Attacker IPs: {YELLOW}{total_unique}{RESET}")

    # Alerts
    print(f"\n{BOLD}{RED}[!] BRUTE FORCE ALERTS:{RESET}")
    if alerts:
        for alert in alerts:
            print(f"\n  {RED}╔══ 🚨 ATTACK DETECTED ══╗{RESET}")
            print(f"  {RED}║{RESET}  IP Address : {alert['ip']}")
            print(f"  {RED}║{RESET}  Attempts   : {alert['attempts']}")
            print(f"  {RED}║{RESET}  Targets    : {alert['targets']}")
            print(f"  {RED}║{RESET}  Time       : {alert['timestamp']}")
            print(f"  {RED}║{RESET}  Status     : 🔴 {alert['status']}")
            print(f"  {RED}╚════════════════════════╝{RESET}")
    else:
        print(f"  {GREEN}✓  No brute force activity detected{RESET}")

    # All Failed Attempts
    print(f"\n{BOLD}[*] ALL FAILED LOGIN ATTEMPTS:{RESET}")
    for ip, data in failed_counts.items():
        colour = RED if data["count"] >= THRESHOLD else YELLOW
        status = "🔴 BLOCKED" if ip in blocked_ips else "🟡 MONITORING"
        print(f"  {colour}IP: {ip:<20} Attempts: {data['count']:<5} Status: {status}{RESET}")

    # Blocked IPs
    print(f"\n{BOLD}[!] CURRENTLY BLOCKED IPs:{RESET}")
    if blocked_ips:
        for ip, data in blocked_ips.items():
            print(f"  {RED}🚫  {ip} — Blocked at {data['timestamp']}{RESET}")
    else:
        print(f"  {GREEN}No IPs currently blocked{RESET}")

    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{GREEN}[✓] Detection Complete! Blocked IPs saved to: {BLOCKED_IPS_FILE}{RESET}\n")


def main():
    print(f"{BOLD}{CYAN}")
    print("  ╔══════════════════════════════════╗")
    print("  ║   BRUTE FORCE ATTACK DETECTOR   ║")
    print("  ║       SOC Defence Tool v1.0     ║")
    print(f"  ╚══════════════════════════════════╝{RESET}\n")

    # Generate sample log
    if not os.path.exists(LOG_FILE):
        generate_sample_log()

    print(f"{CYAN}[*] Loading log file: {LOG_FILE}{RESET}")
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    print(f"{GREEN}[+] Loaded {len(lines)} log entries{RESET}")

    print(f"{CYAN}[*] Parsing events...{RESET}")
    events = parse_logs(lines)

    print(f"{CYAN}[*] Running brute force detection...{RESET}")
    alerts, failed_counts, blocked_ips = detect_brute_force(events)

    display_dashboard(events, alerts, failed_counts, blocked_ips)


if __name__ == "__main__":
    main()
