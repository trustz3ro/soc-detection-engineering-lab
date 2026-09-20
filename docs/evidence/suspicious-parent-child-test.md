# Suspicious Parent/Child Process Detection — Validation Evidence

## Negative Control

The detector was first run against live Sysmon Event ID 1 telemetry with a 15-minute lookback:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\detect_suspicious_parent_child.ps1" -LookbackMinutes 15
```

Observed result:

```text
No suspicious Office parent/child process activity detected in the last 15 minutes.
```

This established a clean baseline before positive testing.

## Synthetic Positive Test

The detector was then run in safe synthetic validation mode:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\detect_suspicious_parent_child.ps1" -TestMode
```

Observed result:

```text
ALERT: Suspicious parent/child process relationship detected.
Time: 09/19/2026 19:45:27
User: LAB\student
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ParentCommandLine: "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" C:\Lab\sample.docx
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -Command "Write-Output SOC-LAB-PARENT-CHILD-TEST"
ProcessId: 4242
ProcessGuid: {00000000-0000-0000-0000-000000004242}
ValidationMode: Synthetic
```

## Validation Outcome

The rule correctly identified the simulated relationship:

```text
WINWORD.EXE -> powershell.exe
```

This confirms that the matching logic works for the targeted parent/child pattern.

## Why Synthetic Validation Was Used

The goal was to validate the detection logic without creating a malicious Office document, enabling macros, or forcing Office to launch a scripting interpreter.

The same rule logic is used for live Sysmon Event ID 1 records and for the synthetic test record.

## Status

Detection #2 for Phase 3: **Validated**

Data source:

- Sysmon Event ID 1 — Process Create

Relevant MITRE ATT&CK context:

- T1059 — Command and Scripting Interpreter
- T1218 — System Binary Proxy Execution, when applicable to the specific child process and behavior
