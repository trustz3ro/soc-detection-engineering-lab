# SOC Detection Engineering Lab Roadmap

## Phase 1 - Build the Logging Environment
**Status: In Progress**
- Deploy Windows and Linux lab endpoints
- Install and configure Sysmon on Windows
- Enable useful Windows auditing
- Select and configure a SIEM/log platform
- Ingest Windows and Linux logs
- Validate timestamps, hostnames, usernames, and event fields

## Phase 2 - Authentication Detections
**Status: Complete**
- Detect repeated failed logins
- Detect a successful login after repeated failures
- Detect password spraying
- Validate Linux and Windows OpenSSH telemetry
- Document false-positive considerations
- Commit test evidence

## Phase 3 - Endpoint / Process Detections
**Status: Complete**
- Detect suspicious PowerShell activity
- Detect privileged-group changes
- Detect unusual parent/child process execution
- Validate Sysmon process, DNS, and network telemetry
- Map detections to MITRE ATT&CK
- Document tuning and false positives

## Phase 4 - Incident Investigations
**Status: Complete**
- Generate controlled suspicious activity
- Triage alerts
- Build timelines
- Correlate process, DNS, network, account, and authentication activity
- Determine scope and severity
- Write incident reports
- Document disposition, remediation, and lessons learned

Completed cases:
- Incident 001 — Suspicious PowerShell Activity
- Incident 002 — Privileged Local Group Membership Change

## Phase 5 - Automation and Enrichment
**Status: Complete**
- Build Python utilities for parsing and summarizing logs
- Extract timestamp, user, host, source IP, source port, and event type
- Detect password spraying
- Correlate failed authentications followed by success within a configurable time window
- Add local IOC enrichment
- Perform reverse-DNS and domain-resolution lookups
- Generate repeatable investigation output
- Document inputs, outputs, assumptions, limitations, and example results

Validated utilities:
- `scripts/analyze_auth_logs.py`
- `scripts/enrich_ioc.py`

## Phase 6 - Portfolio Polish
**Status: Complete**
- Added architecture and workflow diagrams
- Improved the repository landing page for fast recruiter review
- Organized and surfaced strong evidence
- Added recruiter-friendly project summary
- Added resume-ready project bullets
- Featured the project from the GitHub profile README

## Next Expansion

Planned future work:
- select and deploy a SIEM/log platform
- centralize Windows and Linux telemetry
- convert current detection logic into SIEM-native detections
- expand endpoint and identity coverage
- add additional incident investigations using centralized telemetry
