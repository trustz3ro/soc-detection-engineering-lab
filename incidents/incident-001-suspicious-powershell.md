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
