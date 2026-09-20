# Phase 4 Summary — Incident Investigations

## Status

**Complete**

Phase 4 moved the project from alert generation into SOC-style triage and investigation.

## Incident 001 — Suspicious PowerShell Activity

The first case began with a controlled suspicious PowerShell alert using `-ExecutionPolicy Bypass`.

The investigation correlated:
- Sysmon Event ID 1 — Process Create
- Sysmon Event ID 22 — DNS Query
- Sysmon Event ID 3 — Network Connection

A shared ProcessGuid linked the PowerShell process to:
- `github.com` DNS resolution
- a TCP/443 connection to a resolved GitHub address

### Final Assessment
- Severity: Informational / Low
- Disposition: Benign Positive
- Confidence: High

## Incident 002 — Privileged Local Group Membership Change

The second case began with a synthetic Event ID 4732-style alert.

The investigation verified:
- current local Administrators membership
- absence of the synthetic account from the real Administrators group
- no real Event ID 4732 in the investigation window
- nearby Event ID 4624 activity consisted of normal SYSTEM service logons

### Final Assessment
- Severity: Informational
- Disposition: Benign Positive / Synthetic Test
- Confidence: High

## Skills Practiced

- alert validation
- ProcessGuid correlation
- event timeline construction
- endpoint-state verification
- authentication review
- scope determination
- severity assessment
- ATT&CK mapping
- incident disposition
- remediation recommendations
- lessons-learned documentation

## Acceptance Criteria Review

- At least two complete incident investigations documented: **complete**
- Evidence included: **complete**
- Timelines included: **complete**
- Clear disposition for each case: **complete**
- Remediation plan for each case: **complete**

## Next Phase

Phase 5 will focus on automation and enrichment.

The goal is to convert repetitive analyst steps into reusable scripts that can:
- parse log data
- summarize authentication activity
- extract important fields
- enrich indicators
- produce investigation-ready output
