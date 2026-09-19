from collections import defaultdict
from pathlib import Path
import re

log_file = Path("data/sample-logs/password_spray.log")

attempts_by_ip = defaultdict(set)

with log_file.open("r") as file:
    for line in file:
        if "Failed password" not in line:
            continue

        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        user_match = re.search(r"Failed password for (?:invalid user )?(\S+)", line)

        if ip_match and user_match:
            source_ip = ip_match.group(1)
            username = user_match.group(1)
            attempts_by_ip[source_ip].add(username)

threshold = 4
alert_found = False

for source_ip, usernames in attempts_by_ip.items():
    if len(usernames) >= threshold:
        alert_found = True
        print("ALERT: Possible password spraying detected.")
        print("Source IP:", source_ip)
        print("Unique usernames targeted:", len(usernames))
        print("Usernames:", ", ".join(sorted(usernames)))

if not alert_found:
    print("No password spraying pattern detected.")
