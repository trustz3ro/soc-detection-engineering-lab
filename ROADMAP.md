# SOC Detection Engineering Lab Roadmap

## Phase 1 - Build the Logging Environment
- Deploy Windows and Linux lab endpoints
- Install and configure Sysmon on Windows
- Enable useful Windows auditing
- Select and configure a SIEM/log platform
- Ingest Windows and Linux logs
- Validate timestamps, hostnames, usernames, and event fields

## Phase 2 - Authentication Detections
- Detect repeated failed logins
- Detect a successful login after repeated failures
- Detect unusual authentication patterns
- Document false-positive considerations
- Capture screenshots and sample events

## Phase 3 - Endpoint / Process Detections
- Detect suspicious PowerShell activity
- Detect new local administrators or privileged-group changes
- Detect unusual process execution
- Map detections to MITRE ATT&CK

## Phase 4 - Incident Investigations
- Generate controlled suspicious activity in the lab
- Triage alerts
- Build a timeline of related events
- Determine scope and severity
- Write incident reports with remediation recommendations

## Phase 5 - Automation and Enrichment
- Build Python utilities for parsing and summarizing logs
- Add simple IOC/enrichment logic
- Generate repeatable investigation output
- Document script usage and limitations

## Phase 6 - Portfolio Polish
- Add evidence and diagrams
- Refine detection write-ups
- Add resume-ready project bullets
- Link the project from the GitHub profile README
