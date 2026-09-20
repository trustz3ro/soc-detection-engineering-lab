#!/usr/bin/env python3
"""Perform lightweight IOC enrichment for IP addresses and domains."""

from __future__ import annotations

import argparse
import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional


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


@dataclass
class IOCResult:
    indicator: str
    indicator_type: str
    classification: str
    resolved_ips: list[str]
    reverse_dns: Optional[str]
    notes: list[str]


def classify_ip(value: str) -> str:
    ip = ipaddress.ip_address(value)

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

    if ip.is_unspecified:
        return "unspecified"

    return "public"


def enrich_ip(value: str) -> IOCResult:
    ip = ipaddress.ip_address(value)
    classification = classify_ip(value)
    notes: list[str] = []

    reverse_dns = None
    try:
        reverse_dns = socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror, TimeoutError):
        notes.append("No reverse-DNS hostname was returned.")

    if classification == "documentation/test range":
        notes.append(
            "This address belongs to an RFC documentation range and should not be treated as a real external IOC."
        )
    elif classification == "private RFC1918":
        notes.append(
            "This is a private address. Investigate it using internal asset, DHCP, VPN, or endpoint telemetry."
        )
    elif classification == "public":
        notes.append(
            "This is a public IP address. Additional reputation or ASN enrichment may be useful."
        )

    return IOCResult(
        indicator=value,
        indicator_type=f"IPv{ip.version}",
        classification=classification,
        resolved_ips=[str(ip)],
        reverse_dns=reverse_dns,
        notes=notes,
    )


def enrich_domain(value: str) -> IOCResult:
    notes: list[str] = []
    resolved_ips: list[str] = []

    try:
        results = socket.getaddrinfo(value, None)
        resolved_ips = sorted({item[4][0] for item in results})
    except socket.gaierror as exc:
        notes.append(f"DNS resolution failed: {exc}")

    classifications = set()
    for resolved_ip in resolved_ips:
        try:
            classifications.add(classify_ip(resolved_ip))
        except ValueError:
            classifications.add("unparsed")

    if resolved_ips:
        classification = ", ".join(sorted(classifications))
        notes.append(
            "Domain resolution is point-in-time data and may change because of CDNs, load balancing, or DNS updates."
        )
    else:
        classification = "unresolved"

    return IOCResult(
        indicator=value,
        indicator_type="domain",
        classification=classification,
        resolved_ips=resolved_ips,
        reverse_dns=None,
        notes=notes,
    )


def enrich_indicator(value: str) -> IOCResult:
    try:
        ipaddress.ip_address(value)
        return enrich_ip(value)
    except ValueError:
        return enrich_domain(value)


def print_result(result: IOCResult) -> None:
    print("=" * 72)
    print("IOC ENRICHMENT SUMMARY")
    print("=" * 72)
    print(f"Indicator: {result.indicator}")
    print(f"Type: {result.indicator_type}")
    print(f"Classification: {result.classification}")

    if result.resolved_ips:
        print("Resolved / observed IPs:")
        for value in result.resolved_ips:
            print(f"  - {value} ({classify_ip(value)})")
    else:
        print("Resolved / observed IPs:")
        print("  - None")

    print(f"Reverse DNS: {result.reverse_dns or 'None'}")

    print("Notes:")
    if result.notes:
        for note in result.notes:
            print(f"  - {note}")
    else:
        print("  - No additional notes.")

    print()
    print("Analyst note:")
    print(
        "  Enrichment adds context but does not determine whether an indicator is malicious. "
        "Correlate it with endpoint, authentication, DNS, network, and threat-intelligence evidence."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Perform lightweight IOC enrichment for an IP address or domain."
    )
    parser.add_argument(
        "indicator",
        help="IP address or domain name to enrich.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = enrich_indicator(args.indicator.strip())
    print_result(result)


if __name__ == "__main__":
    main()
