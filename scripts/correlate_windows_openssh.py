#!/usr/bin/env python3
"""Find 3+ distinct invalid usernames per agent/source in a 5-minute window."""
import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

PATTERN = re.compile(r"^Invalid user (\S+) from (\S+) port \d+$")


def correlate(events, now, threshold=3, window_seconds=300):
    cutoff = now - timedelta(seconds=window_seconds)
    groups = defaultdict(list)

    for event in events:
        if str(event.get("rule", {}).get("id")) != "100100":
            continue
        agent = event.get("agent", {})
        if agent.get("name") != "Ed_T14":
            continue
        payload = (
            event.get("data", {}).get("win", {})
            .get("eventdata", {}).get("payload", "")
        )
        match = PATTERN.fullmatch(payload)
        if not match:
            continue
        try:
            timestamp = datetime.fromisoformat(
                re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", event["timestamp"].replace("Z", "+00:00"))
            )
        except (KeyError, ValueError, TypeError):
            continue
        if timestamp.tzinfo is None or not cutoff <= timestamp <= now:
            continue
        username, source_ip = match.groups()
        key = (str(agent.get("id", "")), agent["name"], source_ip)
        groups[key].append((timestamp, username))

    results = []
    for (agent_id, agent_name, source_ip), attempts in sorted(groups.items()):
        usernames = sorted({username for _, username in attempts})
        if len(usernames) < threshold:
            continue
        results.append({
            "integration": "openssh_distinct_user_correlation",
            "target_agent_id": agent_id,
            "target_agent_name": agent_name,
            "source_ip": source_ip,
            "unique_users": len(usernames),
            "usernames": usernames,
            "attempts": len(attempts),
            "window_seconds": window_seconds,
            "first_event": min(t for t, _ in attempts).isoformat(),
            "last_event": max(t for t, _ in attempts).isoformat(),
        })
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Wazuh alerts JSON-lines file")
    parser.add_argument("--now", help="Optional ISO timestamp for replay tests")
    args = parser.parse_args()
    now = (
        datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        if args.now else datetime.now(timezone.utc)
    )
    if now.tzinfo is None:
        parser.error("--now must include a timezone")
    events = []
    with open(args.input, encoding="utf-8") as source:
        for line in source:
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    for result in correlate(events, now):
        print(json.dumps(result))


if __name__ == "__main__":
    main()
