# SOC Detection Engineering Lab

A hands-on cybersecurity portfolio project focused on security monitoring, log analysis, detection engineering, incident investigation, and basic response workflows.

## Project Objective

Build a small Security Operations Center (SOC) lab that collects Windows and Linux telemetry, generates realistic security events, detects suspicious behavior, and documents the investigation process.

## Skills Demonstrated

- Security monitoring and log analysis
- Windows Event Logs and Sysmon
- Linux authentication and system logs
- SIEM concepts and log ingestion
- Detection engineering
- MITRE ATT&CK mapping
- Alert triage and incident investigation
- PowerShell activity analysis
- Brute-force and suspicious authentication detection
- Incident documentation
- Python-based log parsing and enrichment

## Planned Architecture

```text
Windows Endpoint + Sysmon ----\
                              \
Windows Server ----------------> SIEM / Log Platform ---> Detection Rules ---> Alerts ---> Investigation
                              /
Linux Endpoint ---------------/
```

## Detection Scenarios

1. Repeated failed logins / brute-force behavior
2. Successful login following repeated failures
3. Suspicious PowerShell execution
4. New local administrator account or privileged group membership
5. Unusual process execution
6. Linux SSH authentication failures
7. Security-relevant account changes

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

- `docs/` - architecture, workflows, detection notes, and incident documentation
- `detections/` - detection logic and rule documentation
- `incidents/` - completed investigation reports
- `scripts/` - PowerShell and Python utilities
- `sample-data/` - sanitized sample log data
- `evidence/` - screenshots and lab evidence

## Project Roadmap

See [ROADMAP.md](ROADMAP.md) for the complete implementation plan.

## Status

**Phase 0 - Repository and detection planning: Complete**  
**Phase 1 - Build log collection environment: Next**

## Author

Edward Johnson  
GitHub: [trustz3ro](https://github.com/trustz3ro)
