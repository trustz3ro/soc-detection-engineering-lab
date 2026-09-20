# Incident Investigation 001 — Suspicious PowerShell Activity

## Scenario

A PowerShell process triggers the lab's suspicious PowerShell detection.

The investigation objective is to determine:

- what PowerShell command executed
- which user launched it
- which parent process launched PowerShell
- whether the process performed DNS lookups
- whether it made network connections
- whether the activity is malicious, benign, or inconclusive

## Primary Evidence Sources

- Sysmon Event ID 1 — Process Create
- Sysmon Event ID 22 — DNS Query
- Sysmon Event ID 3 — Network Connection

## Investigation Helper

`scripts/collect_sysmon_timeline.ps1`

The helper collects Event IDs 1, 3, and 22 and can optionally filter them using a Sysmon `ProcessGuid`.

Example:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\collect_sysmon_timeline.ps1" -LookbackMinutes 10
```

Or, after an alert identifies a ProcessGuid:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\collect_sysmon_timeline.ps1" -LookbackMinutes 10 -ProcessGuid "{PROCESS-GUID-HERE}"
```

## Planned Investigation Workflow

1. Generate a controlled PowerShell alert.
2. Record the ProcessGuid from the alert.
3. Collect matching Sysmon Event IDs 1, 3, and 22.
4. Build a timeline.
5. Determine whether DNS or network activity occurred.
6. Assess scope and severity.
7. Assign a final disposition.
8. Document remediation and lessons learned.

## Expected Disposition

Because the lab test is intentionally generated, the expected final disposition is:

```text
Benign Positive
```

The purpose is to practice a complete SOC investigation workflow using realistic telemetry.


## Investigation Progress — Process-Only Test

A controlled PowerShell event was generated:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-INCIDENT-001'"
```

The suspicious PowerShell detector alerted on:

```text
Time: 09/19/2026 19:56:36
User: Ed_T14\ej975
ProcessId: 9220
ProcessGuid: {0c6a6533-2f44-6aaf-3308-000000005e00}
Indicator: Execution policy bypass
```

The timeline collector was then filtered to that ProcessGuid.

Observed correlated telemetry:

```text
Event ID 1 — Process Create
ProcessId: 9220
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-INCIDENT-001'"
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: Ed_T14\ej975
```

No Event ID 22 DNS or Event ID 3 network records were associated with this ProcessGuid.

### Analyst Interpretation

This result is expected because the test command only printed local text and did not perform DNS resolution or establish a network connection.

This is an important investigation lesson: **absence of DNS or network telemetry can be meaningful when it is consistent with the process behavior.**

A second controlled test will intentionally perform a DNS lookup and HTTPS connectivity check from the same PowerShell process so the investigation can practice multi-event correlation.


## Correlated Multi-Event Timeline

A second controlled PowerShell test intentionally generated process, DNS, and network telemetry from the same PowerShell process:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Resolve-DnsName github.com; Test-NetConnection github.com -Port 443"
```

The suspicious PowerShell detector identified:

```text
Time: 09/19/2026 20:02:41
User: Ed_T14\ej975
ProcessId: 11880
ProcessGuid: {0c6a6533-30b1-6aaf-3d08-000000005e00}
Indicator: Execution policy bypass
```

The timeline collector then correlated Sysmon Event IDs 1, 22, and 3 using the same ProcessGuid.

### Timeline

| Time | Event ID | Evidence | Analyst Interpretation |
| --- | ---: | --- | --- |
| 20:02:41 | 1 | PowerShell process created with `-ExecutionPolicy Bypass`; command line included `Resolve-DnsName github.com` and `Test-NetConnection github.com -Port 443` | Triggering process and command identified |
| 20:02:45 | 22 | `github.com` resolved to `140.82.113.3` | DNS activity from the same PowerShell process |
| 20:02:46 | 22 | `github.com` resolved to `140.82.112.4` | Additional DNS result from the same process |
| 20:02:46 | 22 | `github.com` returned no result for one lookup attempt | One query attempt did not return an address |
| 20:02:46 | 22 | `github.com` resolved to `140.82.114.4` | Additional DNS result from the same process |
| 20:02:47 | 3 | PowerShell connected from `192.168.4.20:54606` to `140.82.112.4:443` over TCP | HTTPS connectivity test confirmed |

### Correlation

All events shared:

```text
ProcessId: 11880
ProcessGuid: {0c6a6533-30b1-6aaf-3d08-000000005e00}
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: Ed_T14\ej975
```

This allowed the activity to be reconstructed as:

```text
PowerShell process created
    -> github.com DNS resolution
    -> GitHub IP returned
    -> TCP/443 connection established
```

## Scope

Observed scope was limited to:

- **Host:** ED_T14
- **User:** Ed_T14\ej975
- **Process:** powershell.exe
- **Process ID:** 11880
- **ProcessGuid:** {0c6a6533-30b1-6aaf-3d08-000000005e00}
- **Domain:** github.com
- **Network destination:** 140.82.112.4:443

No evidence in this test indicated additional hosts, users, persistence, privilege changes, or lateral movement.

## ATT&CK Mapping

| Technique | ID | Evidence |
| --- | --- | --- |
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell executed with `-ExecutionPolicy Bypass` |

No additional ATT&CK technique was assigned solely because the process performed DNS resolution and an HTTPS connectivity check. The observed behavior was intentionally benign and should not be over-mapped.

## Assessment

- **Final Severity:** Informational / Low
- **Disposition:** Benign Positive
- **Confidence:** High

### Rationale

The detection fired correctly because the PowerShell command used `-ExecutionPolicy Bypass`, which is an intentionally monitored indicator.

The surrounding telemetry matched the exact lab command:

- the process command line explicitly requested DNS resolution for `github.com`
- Event ID 22 recorded the corresponding DNS queries
- Event ID 3 recorded the expected TCP/443 connection
- all events shared the same ProcessGuid and ProcessId
- the activity was intentionally generated for lab validation

There was no evidence of malicious payload execution, persistence, privilege escalation, unauthorized account changes, or broader host impact.

## Recommended Response / Remediation

Because this was controlled lab activity:

- no containment action is required
- retain the evidence as a training case
- keep the detection enabled
- consider severity tuning based on indicator count, parent process, destination reputation, and correlated network behavior
- continue using ProcessGuid-based correlation during PowerShell investigations

## Lessons Learned

1. ProcessGuid is highly useful for correlating Sysmon Event IDs 1, 22, and 3.
2. A suspicious indicator does not automatically mean the activity is malicious.
3. Command-line context is critical to understanding intent.
4. DNS and network telemetry can confirm what a process actually did after execution.
5. A clean incident disposition requires both detection evidence and contextual analysis.
6. Not every alert requires remediation; some are benign positives that still validate the detection.

## Final Status

Incident Investigation 001: **Complete**

Disposition: **Benign Positive**
