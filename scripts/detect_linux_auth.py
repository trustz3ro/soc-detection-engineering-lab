from collections import defaultdict, Counter
import re

log_file = "/var/log/auth.log"

users_by_ip = defaultdict(set)
attempts_by_ip = Counter()

pattern = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+)"
)

with open(log_file, "r") as file:
    for line in file:
        match = pattern.search(line)

        if match:
            username = match.group(1)
            source_ip = match.group(2)

            users_by_ip[source_ip].add(username)
            attempts_by_ip[source_ip] += 1

threshold = 3
alert_found = False

for source_ip, usernames in users_by_ip.items():
    if len(usernames) >= threshold:
        alert_found = True

        print("ALERT: Possible password spraying detected.")
        print("Source IP:", source_ip)
        print("Failed login attempts:", attempts_by_ip[source_ip])
        print("Unique usernames targeted:", len(usernames))
        print("Usernames:", ", ".join(sorted(usernames)))
        print()

if not alert_found:
    print("No password spraying pattern detected.")
