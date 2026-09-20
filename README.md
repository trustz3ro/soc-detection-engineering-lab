# SOC Detection Engineering Lab

A hands-on cybersecurity portfolio project focused on security monitoring, authentication analytics, endpoint telemetry, detection engineering, incident investigation, automation, enrichment, and response workflows.

## Project Objective

Build a small Security Operations Center (SOC) lab that collects Windows and Linux telemetry, generates controlled security events, detects suspicious behavior, automates repetitive analysis, and documents the investigation process.

## Current Milestone

**Phase 5 — Automation and Enrichment: Complete**

The lab now includes validated authentication and endpoint detections, two complete incident investigations, and Python-based investigation automation.

### Completed Incident Investigations

1. **Suspicious PowerShell Activity**
   - Correlated Sysmon Event IDs 1, 22, and 3
   - Tracked one PowerShell process with a shared ProcessGuid
   - Built a process -> DNS -> network timeline
   - Final disposition: Benign Positive

2. **Privileged Local Group Membership Change**
   - Validated a synthetic Event ID 4732 alert
   - Compared the alert against real local Administrators membership
   - Verified no real Event ID 4732 occurred
   - Reviewed nearby 4624 logon activity
   - Final disposition: Benign Positive / Synthetic Test

## Validated Detections

### Authentication
- Repeated failed SSH logins followed by success
- Password spraying across multiple usernames
- Native Linux authentication detection
- Native Windows OpenSSH password-spray detection

### Endpoint / Process
- Suspicious PowerShell execution
- Suspicious Office parent/child process relationship
- Privileged local Administrators group membership change

## Automation and Enrichment

### Authentication Analyzer

`scripts/analyze_auth_logs.py`

Capabilities:
- parses supported OpenSSH authentication logs
- extracts timestamp, host, username, source IP, source port, and event type
- summarizes failed and successful authentication activity
- detects password-spray behavior
- correlates failures followed by success within a configurable time window
- calculates elapsed time
- optionally enriches observed source IPs in the same investigation run

### IOC Enrichment Utility

`scripts/enrich_ioc.py`

Capabilities:
- accepts IPv4, IPv6, and domain indicators
- classifies documentation/test, RFC1918, loopback, link-local, multicast, unspecified, and public IPs
- performs reverse DNS for IP addresses when available
- resolves domains to current IP addresses
- produces analyst-focused context without assigning malicious/benign verdicts

## Skills Demonstrated

- Security monitoring and log analysis
- Linux authentication log analysis
- Windows OpenSSH telemetry analysis
- Windows Security event analysis
- Sysmon Event IDs 1, 3, and 22
- Process and parent/child relationship analysis
- DNS and network-event correlation
- Detection engineering and tuning
- Thresholding and lookback windows
- False-positive analysis
- MITRE ATT&CK mapping
- Incident triage
- Timeline construction
- Scope and severity assessment
- Disposition and remediation decisions
- Python log parsing and automation
- Time-window event correlation
- IOC enrichment
- Reverse DNS
- PowerShell detection scripting
- Git/GitHub project workflow
- Technical documentation

## Lab Environment

```text
Mac mini
   |
   +--> OrbStack Ubuntu
   |      +--> Linux auth.log
   |      +--> Python detections
   |
   +--> Tailscale network
          |
          +--> Windows ThinkPad
                 +--> OpenSSH
                 +--> Windows Security log
                 +--> Sysmon
                 +--> PowerShell detections
```

## Investigation Workflow

1. Alert generated
2. Validate event source and timestamp
3. Identify affected user and host
4. Review surrounding authentication and process activity
5. Correlate related events
6. Enrich relevant indicators
7. Map behavior to MITRE ATT&CK
8. Determine scope and severity
9. Assign a disposition
10. Document remediation and lessons learned

## Repository Structure

- `docs/` — detection documentation, learning notes, summaries, and evidence
- `data/sample-logs/` — sanitized synthetic authentication data
- `scripts/` — Python and PowerShell detection, investigation, automation, and enrichment utilities
- `incidents/` — completed incident reports and templates
- `configs/` — lab configurations such as Sysmon
- `detections/` — future SIEM/detection-rule content
- `evidence/` — future screenshots and visual lab evidence

## Current Status

- **Repository and architecture planning:** Complete
- **Authentication detections:** Complete
- **Native Linux authentication validation:** Complete
- **Native Windows OpenSSH validation:** Complete
- **Windows Sysmon telemetry validation:** Complete
- **Endpoint / process detections:** 3 validated
- **MITRE ATT&CK mapping:** Documented for current detections
- **Incident investigations:** 2 complete
- **Phase 5 automation and enrichment:** Complete
- **Phase 6 portfolio polish:** Starting
- **SIEM ingestion:** Planned

## Portfolio Goal

This project demonstrates practical SOC and detection-engineering skills through working code, reproducible test data, native Windows and Linux telemetry, documented detection logic, ATT&CK mapping, tuning decisions, event correlation, incident investigation, Python automation, and IOC enrichment.

## Author

Edward Johnson  
GitHub: [trustz3ro](https://github.com/trustz3ro)
