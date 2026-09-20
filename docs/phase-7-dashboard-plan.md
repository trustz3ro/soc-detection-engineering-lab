# Phase 7 Dashboard Plan

## Dashboard Goal

Provide a single SOC view that answers:

- What authentication activity is occurring?
- Which source IPs and usernames are most active?
- What suspicious PowerShell activity is occurring?
- Are privileged local-group changes occurring?
- Which endpoint is generating the activity?

## Planned Panels

### Authentication Overview
- failed authentications over time
- successful authentications over time
- failed-to-success ratio
- top source IPs
- top targeted usernames
- authentication events by host

### Endpoint / Process Overview
- PowerShell process creations
- suspicious PowerShell command-line matches
- Sysmon Event ID 1 volume
- network connections from PowerShell
- DNS queries from PowerShell

### Account / Privilege Overview
- Event ID 4732 count
- accounts added to local groups
- actors making group changes
- target groups

### Cross-Platform Overview
- Windows event volume
- Linux authentication event volume
- top hosts by alert count
- alerts by rule/severity
- timeline of recent notable activity

## Recruiter / Interview Value

The dashboard should make it easy to demonstrate that the lab is not only collecting logs, but turning telemetry into:
- detections
- alert context
- investigation pivots
- actionable analyst views
