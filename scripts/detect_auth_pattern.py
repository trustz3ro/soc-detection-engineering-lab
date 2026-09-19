
from pathlib import Path
import re

log_file = Path("data/sample-logs/auth.log")

failed_attempts = 0
success_detected = False
source_ip = None
username = None

with log_file.open("r") as file:
    for line in file:
        if "Failed password" in line:
            failed_attempts += 1

            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                source_ip = ip_match.group(1)

        if "Accepted password" in line and failed_attempts >= 3:
            success_detected = True

            user_match = re.search(r"Accepted password for (\S+)", line)
            if user_match:
                username = user_match.group(1)

print("Failed login attempts:", failed_attempts)

if success_detected:
    print("ALERT: Successful login detected after multiple failed attempts.")
    print("Source IP:", source_ip)
    print("Username:", username)
else:
    print("No suspicious authentication pattern detected.")
