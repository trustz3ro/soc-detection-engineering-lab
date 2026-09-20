# Incident Investigation Report

## Case Information

- **Case ID:**
- **Date / Time:**
- **Analyst:** Edward Johnson
- **Host(s):**
- **User(s):**
- **Detection / Alert:**
- **Initial Severity:**

## 1. Alert Summary

Describe what triggered the investigation.

Include:
- detection name
- event source
- timestamp
- host
- user
- source/destination information when relevant

## 2. Initial Triage

Record the first questions answered:

- Is the alert expected or unexpected?
- Is the telemetry complete?
- Is the activity still ongoing?
- Which user and endpoint are affected?
- Is there an obvious authorized explanation?

## 3. Evidence Collected

Document relevant evidence.

Examples:
- Sysmon Event ID 1
- Sysmon Event ID 3
- Sysmon Event ID 22
- Windows Security events
- OpenSSH events
- Linux auth.log
- process command lines
- source/destination IP addresses
- account changes

## 4. Timeline

| Time | Host | User | Event / Evidence | Analyst Interpretation |
| --- | --- | --- | --- | --- |
| | | | | |

## 5. Correlation

Explain how the events relate.

Example:

```text
Process creation
    -> DNS lookup
    -> network connection
    -> authentication or account activity
```

## 6. Scope

Document:
- affected accounts
- affected hosts
- source systems
- destination systems
- related processes
- related IP addresses or domains

## 7. ATT&CK Mapping

Document only techniques supported by the observed behavior.

| Technique | ID | Evidence |
| --- | --- | --- |
| | | |

## 8. Assessment

- **Final Severity:**
- **Disposition:** True Positive / Benign Positive / False Positive / Inconclusive
- **Confidence:**

Explain why.

## 9. Recommended Response / Remediation

Examples:
- disable or reset an account
- remove unauthorized group membership
- isolate an endpoint
- block an IP/domain
- review related hosts
- tune a detection
- document approved administrative activity

## 10. Lessons Learned

Record:
- what worked
- what was missing
- what telemetry helped most
- what detection tuning is needed
- what should be automated next

## 11. Evidence References

List repository evidence files, screenshots, commands, and relevant log excerpts.
