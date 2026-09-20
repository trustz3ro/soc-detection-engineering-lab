# Suspicious PowerShell Detection — Validation Evidence

## Controlled Test

A benign PowerShell command was executed to generate suspicious-looking telemetry:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-LAB-TEST'"
```

## Detector Output

The detector generated an alert for the controlled test:

```text
ALERT: Suspicious PowerShell execution detected.
User: Ed_T14\ej975
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-LAB-TEST'"
Indicators: Execution policy bypass
Indicator count: 1
```

The detector also surfaced earlier hidden-window tests still inside the lookback window:

```text
Indicators: Execution policy bypass, Hidden window
Indicator count: 2
```

## Self-Alert Observation

The detector initially alerted on its own invocation because it was launched with:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\detect_suspicious_powershell.ps1"
```

The rule therefore matched `ExecutionPolicy Bypass` in the detector's own command line.

The script was subsequently tuned to suppress only its own invocation while preserving the broader bypass detection.

## Outcome

Status: **Validated**

Data source:

- Sysmon Event ID 1 — Process Create

MITRE ATT&CK:

- T1059.001 — Command and Scripting Interpreter: PowerShell
