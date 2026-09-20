# Recruiter Project Summary

## SOC Detection Engineering Lab

Built a cross-platform SOC lab using Windows, Linux, Sysmon, OpenSSH, Python, and PowerShell to practice detection engineering and incident investigation.

### What the Project Demonstrates

- Created authentication detections for repeated failures, failed-logins-followed-by-success, and password spraying.
- Built endpoint detections for suspicious PowerShell, suspicious Office parent/child relationships, and privileged local group changes.
- Validated Windows telemetry using Sysmon Event IDs 1, 3, and 22 plus Security Event IDs 4624, 4625, and 4732.
- Correlated process creation, DNS resolution, and network connections using ProcessGuid.
- Completed two documented incident investigations with timelines, scope, severity, ATT&CK mapping, disposition, and remediation.
- Built Python automation to parse SSH logs, extract security-relevant fields, detect patterns within configurable time windows, and generate investigation-ready summaries.
- Added lightweight IOC enrichment for IP addresses and domains, including network classification, DNS resolution, and reverse DNS.
- Documented false positives, safe validation methods, assumptions, limitations, and analyst decision points.

### Technical Stack

Python • PowerShell • Sysmon • Windows Event Logs • Linux • OpenSSH • Tailscale • Git • GitHub • MITRE ATT&CK

### Strongest Evidence

- [Incident 001 — Suspicious PowerShell](../incidents/incident-001-suspicious-powershell.md)
- [Incident 002 — Privileged Group Change](../incidents/incident-002-privileged-group-change.md)
- [Authentication Automation Results](evidence/auth-log-automation-results.md)
- [IOC Enrichment Results](evidence/ioc-enrichment-results.md)

### Interview Talking Point

This project was built to practice the analyst workflow rather than only write detection rules. Each alert is validated against the underlying telemetry, correlated with related events, investigated for scope, and assigned a documented disposition.
