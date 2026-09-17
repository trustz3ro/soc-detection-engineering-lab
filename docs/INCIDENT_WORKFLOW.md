# SOC Incident Investigation Workflow

## 1. Alert Intake
Record the alert name, timestamp, source system, affected host, user, and triggering detection.

## 2. Initial Validation
Confirm the event is real and determine whether the behavior is expected, benign, suspicious, or clearly malicious.

## 3. Scope the Activity
Review related authentication, process, network, and account events around the same time window.

## 4. Build a Timeline
Document the sequence of events so the investigation can be followed from initial activity through disposition.

## 5. Map Relevant Behavior
Map applicable activity to MITRE ATT&CK techniques where appropriate.

## 6. Determine Severity
Consider account privilege, affected systems, persistence, lateral movement indicators, and possible business impact.

## 7. Recommend Response
Possible actions may include password reset, account disablement, host isolation, blocking indicators, removing unauthorized privileges, or increasing monitoring.

## 8. Document the Case
Capture evidence, findings, assumptions, limitations, disposition, and remediation recommendations.

## Example Incident Report Sections
- Executive summary
- Alert details
- Timeline
- Evidence reviewed
- Analysis
- MITRE ATT&CK mapping
- Severity and disposition
- Recommended remediation
- Lessons learned
