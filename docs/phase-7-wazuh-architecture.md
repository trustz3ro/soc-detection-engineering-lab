# Phase 7 Wazuh Architecture Plan

## Objective

Centralize Windows and Linux security telemetry in Wazuh and reproduce existing detection logic as SIEM-native rules and queries.

## Planned Architecture

```mermaid
flowchart LR
    MM[Mac mini]
    WZ[OrbStack Ubuntu 24.04 ARM64<br/>wazuh-siem<br/>192.168.139.25]
    WIN[Windows ThinkPad<br/>ED_T14]
    LNX[OrbStack Ubuntu<br/>homelab-ubuntu]

    MM --> WZ
    WIN -->|Wazuh Agent| WZ
    LNX -->|Wazuh Agent / log collection| WZ

    WIN --> WS1[Sysmon Event IDs 1,3,22]
    WIN --> WS2[Security 4624,4625,4732]
    WIN --> WS3[OpenSSH Operational]
    LNX --> LS1[/var/log/auth.log]

    WS1 --> WZ
    WS2 --> WZ
    WS3 --> WZ
    LS1 --> WZ

    WZ --> RULES[SIEM-native rules]
    WZ --> DASH[Dashboards]
    WZ --> ALERTS[Alerts]
    ALERTS --> TRIAGE[Investigation]
```

## Wazuh Host

- Hostname: `wazuh-siem`
- OS: Ubuntu 24.04 LTS
- Architecture: ARM64 / aarch64
- IP: `192.168.139.25/24`
- VM disk quota target: 60 GiB
- Current effective root availability observed during prep: approximately mid-40 GiB
- Current guest memory: approximately 4 GiB
- Connectivity to `packages.wazuh.com`: validated

## Windows ThinkPad Telemetry

Host: `ED_T14`

Planned collection:
- Sysmon Operational
- Windows Security
- Windows OpenSSH Operational

Priority event IDs:
- Sysmon 1 — Process Create
- Sysmon 3 — Network Connect
- Sysmon 22 — DNS Query
- Security 4624 — Successful Logon
- Security 4625 — Failed Logon
- Security 4732 — Member Added to Local Security Group

## Linux Telemetry

Host: `homelab-ubuntu`

Planned collection:
- `/var/log/auth.log`
- SSH authentication failures
- successful SSH authentication
- usernames
- source IP addresses

## Detection Migration Priority

1. Windows OpenSSH password spraying
2. Suspicious PowerShell execution
3. Privileged local Administrators group change

These three were selected because they already have known-good validation cases and evidence in the repository.

## Resource Note

The current Wazuh VM is below the ideal memory recommendation for a small all-in-one deployment. Installation and indexing behavior should be monitored closely, and retention/indexing volume should remain conservative until resource usage is measured.
