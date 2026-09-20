# Suspicious PowerShell Detection

## Objective

Detect potentially suspicious PowerShell execution using Sysmon Event ID 1 process-creation telemetry.

## Data Source

`Microsoft-Windows-Sysmon/Operational`

Event:

`Sysmon Event ID 1 — Process Create`

## Detection Script

`scripts/detect_suspicious_powershell.ps1`

The script reviews recent Sysmon process-creation events and focuses on:

- `powershell.exe`
- `pwsh.exe`

It then evaluates command-line indicators associated with higher-risk PowerShell behavior.

Current indicators include:

- encoded commands
- `ExecutionPolicy Bypass`
- hidden window execution
- `Invoke-Expression` / `IEX`
- `DownloadString`
- `Invoke-WebRequest`

## Why These Indicators Matter

These options and functions are not automatically malicious. Administrators and automation tools can use them legitimately.

They are useful detection signals because attackers also commonly use PowerShell for:

- execution
- payload retrieval
- command obfuscation
- defense evasion
- in-memory activity

The analyst must review the process context before deciding whether the activity is malicious.

## Important Investigation Fields

When an alert fires, review:

- User
- Image
- CommandLine
- ParentImage
- ParentCommandLine
- ProcessId
- ProcessGuid
- matched indicators
- nearby Event ID 3 network connections
- nearby Event ID 22 DNS queries

## Controlled Test

A benign lab command can be used to generate a detectable process without downloading or executing malicious content:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Write-Output 'SOC-LAB-TEST'"
```

Expected indicators:

- Execution policy bypass
- Hidden window

## False Positives

Possible legitimate causes include:

- administrative scripts
- software deployment tools
- endpoint-management products
- developer workflows
- troubleshooting commands
- automation frameworks

## Tuning Ideas

Future improvements:

- require multiple indicators for higher-severity alerts
- allowlist known administrative scripts or parent processes
- add signer/hash reputation
- add a time window around correlated DNS/network activity
- detect suspicious parent/child combinations
- distinguish Windows PowerShell from PowerShell 7

## MITRE ATT&CK

Primary mapping:

- **T1059.001 — Command and Scripting Interpreter: PowerShell**

Depending on the observed command, additional mappings may apply, but they should be based on the actual behavior rather than assigned automatically.
