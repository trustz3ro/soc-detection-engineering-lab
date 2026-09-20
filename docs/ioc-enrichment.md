# IOC Enrichment Utility

## Objective

Provide lightweight, repeatable context for IP addresses and domain names during SOC investigations.

## Script

`scripts/enrich_ioc.py`

## Supported Indicator Types

- IPv4 addresses
- IPv6 addresses
- domain names

## Example Usage

Enrich a public domain:

```powershell
python .\scripts\enrich_ioc.py github.com
```

Enrich a synthetic lab IP:

```powershell
python .\scripts\enrich_ioc.py 198.51.100.25
```

Enrich a private address:

```powershell
python .\scripts\enrich_ioc.py 192.168.4.20
```

## Enrichment Performed

For IP addresses, the script reports:

- IP version
- address classification
- reverse-DNS hostname when available
- analyst notes based on the address type

For domains, the script reports:

- DNS resolution results
- classification of each resolved IP
- point-in-time resolution caveat

## Address Classifications

The utility identifies:

- RFC documentation/test ranges
- RFC1918 private ranges
- loopback
- link-local
- multicast
- unspecified addresses
- public addresses

## SOC Use

This utility helps an analyst quickly distinguish between:

- synthetic lab indicators
- internal/private infrastructure
- externally routable indicators
- domain names that resolve to one or more addresses

It is intended to support triage, not make a malicious/benign determination.

## Limitations

The current version does not:

- query commercial threat-intelligence services
- provide reputation scores
- retrieve ASN or geolocation data
- prove ownership or intent
- preserve historical DNS results
- determine whether an IOC is malicious

DNS and reverse-DNS results are point-in-time observations and may change.
