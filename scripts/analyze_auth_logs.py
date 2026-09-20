#!/usr/bin/env python3
"""Summarize SSH authentication activity for SOC investigation use."""

from __future__ import annotations

import argparse
import ipaddress
import re
from collections import defaultdict
from pathlib import Path

EVENT_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted) password for "
    r"(?:(?P<invalid>invalid user)\s+)?"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+ssh2$"
)

TEST_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def classify_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid/unparsed"

    if any(ip in network for network in TEST_NETS):
        return "documentation/test range"

    if any(ip in network for network in RFC1918):
        return "private RFC1918"

    if ip.is_loopback:
        return "loopback"

    if ip.is_link_local:
        return "link-local"

    if ip.is_multicast:
        return "multicast"

    return "public"


def parse_log(path: Path) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            match = EVENT_PATTERN.match(line)

            if not match:
                continue

            item = match.groupdict()
            item["line_number"] = str(line_number)
            item["event_type"] = (
                "authentication_failure"
                if item["result"] == "Failed"
                else "authentication_success"
            )
            item["ip_class"] = classify_ip(item["ip"])
            events.append(item)

    return events


def analyze(events: list[dict[str, str]], spray_threshold: int) -> dict:
    failed_by_ip: dict[str, list[dict[str, str]]] = defaultdict(list)
    success_by_ip: dict[str, list[dict[str, str]]] = defaultdict(list)

    for event in events:
        if event["event_type"] == "authentication_failure":
            failed_by_ip[event["ip"]].append(event)
        else:
            success_by_ip[event["ip"]].append(event)

    indicators: list[str] = []

    for source_ip, failures in failed_by_ip.items():
        unique_users = sorted({event["user"] for event in failures})

        if len(unique_users) >= spray_threshold:
            indicators.append(
                f"Possible password spray: {source_ip} targeted "
                f"{len(unique_users)} unique usernames "
                f"({', '.join(unique_users)})."
            )

        if source_ip in success_by_ip:
            indicators.append(
                f"Failed-then-success pattern: {source_ip} had "
                f"{len(failures)} failed attempt(s) and "
                f"{len(success_by_ip[source_ip])} successful login(s)."
            )

    return {
        "failed_by_ip": failed_by_ip,
        "success_by_ip": success_by_ip,
        "indicators": indicators,
    }


def print_report(path: Path, events: list[dict[str, str]], analysis: dict) -> None:
    failures = [e for e in events if e["event_type"] == "authentication_failure"]
    successes = [e for e in events if e["event_type"] == "authentication_success"]

    print("=" * 72)
    print("SSH AUTHENTICATION INVESTIGATION SUMMARY")
    print("=" * 72)
    print(f"Input file: {path}")
    print(f"Parsed events: {len(events)}")
    print(f"Failed authentications: {len(failures)}")
    print(f"Successful authentications: {len(successes)}")
    print()

    if events:
        hosts = sorted({event["host"] for event in events})
        users = sorted({event["user"] for event in events})
        source_ips = sorted({event["ip"] for event in events})

        print("Hosts:")
        for host in hosts:
            print(f"  - {host}")

        print("Users observed:")
        for user in users:
            print(f"  - {user}")

        print("Source IPs:")
        for source_ip in source_ips:
            print(f"  - {source_ip} ({classify_ip(source_ip)})")
        print()

    print("Event timeline:")
    if not events:
        print("  No supported SSH password authentication events parsed.")
    else:
        for event in events:
            marker = "FAIL" if event["event_type"] == "authentication_failure" else "SUCCESS"
            invalid = " [invalid user]" if event.get("invalid") else ""
            print(
                f"  {event['timestamp']} | {marker:<7} | "
                f"user={event['user']}{invalid} | "
                f"src={event['ip']}:{event['port']} | host={event['host']}"
            )
    print()

    print("Indicators:")
    if analysis["indicators"]:
        for indicator in analysis["indicators"]:
            print(f"  - {indicator}")
    else:
        print("  - No configured investigation indicators found.")

    print()
    print("Analyst note:")
    print(
        "  Indicators are triage signals, not proof of malicious activity. "
        "Validate source, timing, account context, and surrounding telemetry."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse SSH authentication logs and produce an investigation summary."
    )
    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to an SSH authentication log file.",
    )
    parser.add_argument(
        "--spray-threshold",
        type=int,
        default=4,
        help="Unique failed usernames from one source required to flag possible spraying (default: 4).",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.spray_threshold < 1:
        parser.error("--spray-threshold must be at least 1")

    if not args.log_file.exists():
        parser.error(f"log file not found: {args.log_file}")

    events = parse_log(args.log_file)
    analysis = analyze(events, args.spray_threshold)
    print_report(args.log_file, events, analysis)


if __name__ == "__main__":
    main()
