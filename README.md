# SOC Detection Engineering Lab

A hands-on cybersecurity portfolio project focused on security monitoring, authentication analytics, endpoint telemetry, detection engineering, incident investigation, and response workflows.

## Project Objective

Build a small Security Operations Center (SOC) lab that collects Windows and Linux telemetry, generates controlled security events, detects suspicious behavior, and documents the investigation process.

## Current Milestone

**Phase 3 — Endpoint / Process Detections: Complete**

The lab now includes validated authentication detections plus three endpoint-focused detections:

1. **Suspicious PowerShell execution**
   - Uses Sysmon Event ID 1
   - Reviews PowerShell command lines for higher-risk indicators
   - Includes self-alert suppression and configurable lookback

2. **Suspicious Office parent/child process relationship**
   - Uses Sysmon Event ID 1
   - Detects Office-style parent processes launching scripting interpreters or selected LOLBins
   - Includes a safe synthetic validation mode

3. **Privileged local group membership change**
   - Uses Windows Security Event ID 4732
   - Detects additions to the local Administrators group
   - Includes a safe synthetic validation mode

Authentication detections also include:
- repeated failed SSH logins followed by a successful login
- password spraying across multiple usernames
- native Linux authentication validation
- native Windows OpenSSH authentication validation

## Example Detection Output

```text
ALERT: Suspicious PowerShell execution detected.
User: Ed_T14\ej975
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Indicators: Execution policy bypass
Indicator count: 1
```

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
- Python log parsing
- PowerShell detection scripting
- Git/GitHub project workflow
- Technical documentation
- SOC triage concepts

## Lab Environment

Current lab:

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

Planned telemetry architecture:

```text
Windows Endpoint + Sysmon ----\
                              \
Windows Server ----------------> SIEM / Log Platform ---> Detection Rules ---> Alerts ---> Investigation
                              /
Linux Endpoint ---------------/
```

## Implemented Detections

### Authentication

- `scripts/detect_auth_pattern.py`
- `scripts/detect_password_spray.py`
- `scripts/detect_linux_auth.py`
- `scripts/detect_windows_ssh_spray.ps1`

### Endpoint / Process

- `scripts/detect_suspicious_powershell.ps1`
- `scripts/detect_suspicious_parent_child.ps1`
- `scripts/detect_admin_group_addition.ps1`

## Evidence and Documentation

Detection documentation is stored under:

- `docs/`
- `docs/evidence/`

Learning notes include:

- `docs/learning-notes-authentication-detection.md`
- `docs/learning-notes-sysmon.md`

## Investigation Workflow

1. Alert generated
2. Validate event source and timestamp
3. Identify affected user and host
4. Review surrounding authentication and process activity
5. Correlate related events
6. Map behavior to MITRE ATT&CK
7. Determine severity and disposition
8. Document findings and recommended remediation

## Repository Structure

- `docs/` — detection documentation, learning notes, evidence, architecture, and workflows
- `data/sample-logs/` — sanitized synthetic authentication data
- `scripts/` — Python and PowerShell detection utilities
- `detections/` — future SIEM/detection-rule content
- `incidents/` — incident investigation reports and templates
- `configs/` — lab configurations such as Sysmon
- `evidence/` — future screenshots and visual lab evidence

## Project Roadmap

See [ROADMAP.md](ROADMAP.md) for the full implementation plan.

## Current Status

- **Repository and architecture planning:** Complete
- **Authentication detection prototypes:** Complete
- **Native Linux authentication validation:** Complete
- **Native Windows OpenSSH validation:** Complete
- **Windows Sysmon telemetry validation:** Complete
- **Endpoint / process detections:** 3 validated
- **MITRE ATT&CK mapping:** Documented for current detections
- **Incident investigations:** Starting
- **SIEM ingestion:** Planned
- **Python enrichment/automation:** Planned

## Portfolio Goal

This project demonstrates practical SOC and detection-engineering skills through working code, reproducible test data, native Windows and Linux telemetry, documented detection logic, ATT&CK mapping, tuning decisions, and validation evidence.

## Author

Edward Johnson  
GitHub: [trustz3ro](https://github.com/trustz3ro)
