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
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-LAB-TEST'"
```

Expected indicator:

- Execution policy bypass

The earlier hidden-window test was removed from the primary validation procedure after it caused PowerShell session instability on the lab endpoint. Hidden-window detection remains in the rule logic, but it is not required for the controlled test.

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


## Validation Result

The first live validation successfully triggered on the controlled PowerShell command.

Observed alert:

```text
ALERT: Suspicious PowerShell execution detected.
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-LAB-TEST'"
Indicators: Execution policy bypass
Indicator count: 1
```

Earlier test activity using `-WindowStyle Hidden` was also still inside the detector's lookback window, so those historical events were returned as additional alerts.

### Detector Self-Alert Lesson

The initial detector invocation itself used:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\detect_suspicious_powershell.ps1"
```

Because the detection logic looks for `ExecutionPolicy Bypass`, it correctly matched its own command line.

This is a useful detection-engineering lesson: **a technically correct rule can still create an operational false positive**.

The detector was updated to exclude only its own script invocation:

```text
detect_suspicious_powershell.ps1
```

This keeps the broader `ExecutionPolicy Bypass` detection intact for other PowerShell activity.

The script now also accepts a configurable lookback period:

```powershell
.\scripts\detect_suspicious_powershell.ps1 -LookbackMinutes 1
```

This makes controlled testing cleaner by limiting results to very recent telemetry.
