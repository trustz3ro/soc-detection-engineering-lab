# SOC Detection Engineering Lab

A hands-on cybersecurity portfolio project focused on security monitoring, authentication analytics, detection engineering, incident investigation, and response workflows.

## Project Objective

Build a small Security Operations Center (SOC) lab that collects Windows and Linux telemetry, generates realistic security events, detects suspicious behavior, and documents the investigation process.

## Current Milestone

Two authentication detections are now implemented and tested:

1. **Repeated failed logins followed by a successful login**
   - Counts failed SSH authentication attempts
   - Detects a later successful login
   - Extracts the source IP and successful-login username

2. **Password spraying**
   - Groups failed SSH logins by source IP
   - Tracks unique usernames targeted
   - Alerts when one source targets multiple accounts
   - Maps to **MITRE ATT&CK T1110.003 — Password Spraying**

## Example Detection Output

```text
ALERT: Possible password spraying detected.
Source IP: 198.51.100.25
Unique usernames targeted: 5
Usernames: admin, edwardjohnson, guest, root, support
```

## Skills Demonstrated

- Security monitoring and log analysis
- Linux authentication log analysis
- Detection engineering
- MITRE ATT&CK mapping
- Alert logic and thresholding
- Authentication attack-pattern analysis
- False-positive analysis
- Python log parsing
- Git/GitHub project workflow
- Technical documentation
- SOC triage concepts

## Lab Environment

Current development environment:

```text
Mac mini
   |
   v
OrbStack
   |
   v
Ubuntu Lab
   |
   +--> Python detection scripts
   +--> Synthetic authentication logs
   +--> Git / GitHub
```

Planned telemetry architecture:

```text
Windows Endpoint + Sysmon ----\
                              \
Windows Server ----------------> SIEM / Log Platform ---> Detection Rules ---> Alerts ---> Investigation
                              /
Linux Endpoint ---------------/
```

## Implemented Files

### Detection 1 — Failed Logins Followed by Success

- `data/sample-logs/auth.log`
- `scripts/detect_auth_pattern.py`
- `docs/authentication-detection.md`

### Detection 2 — Password Spraying

- `data/sample-logs/password_spray.log`
- `scripts/detect_password_spray.py`
- `docs/password-spray-detection.md`
- `docs/evidence/password-spray-test.md`

## Detection Scenarios

### Implemented
- Repeated failed SSH logins
- Successful login after repeated failures
- Password spraying across multiple usernames

### Planned
- Suspicious PowerShell execution
- New local administrator or privileged-group membership
- Unusual process execution
- Native Linux SSH telemetry
- Windows authentication telemetry
- Security-relevant account changes

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

- `docs/` — detection documentation, evidence, architecture, and workflows
- `data/sample-logs/` — sanitized synthetic authentication data
- `scripts/` — Python detection and analysis utilities
- `detections/` — future SIEM/detection-rule content
- `incidents/` — future completed investigation reports
- `evidence/` — future screenshots and visual lab evidence

## Project Roadmap

See [ROADMAP.md](ROADMAP.md) for the full implementation plan.

## Current Status

- **Repository and architecture planning:** Complete
- **Authentication detection prototypes:** 2 working detections
- **MITRE ATT&CK mapping:** In progress
- **Native Linux telemetry validation:** Next
- **Windows/Sysmon telemetry:** Planned
- **SIEM ingestion:** Planned
- **Incident investigations:** Planned
- **Python enrichment/automation:** Planned

## Portfolio Goal

This project is designed to demonstrate practical SOC and detection-engineering skills through working code, reproducible test data, documented detection logic, ATT&CK mapping, and evidence of successful testing.

## Author

Edward Johnson  
GitHub: [trustz3ro](https://github.com/trustz3ro)
