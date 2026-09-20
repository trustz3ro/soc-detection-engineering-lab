# Phase 3 Summary — Endpoint and PowerShell Detections

## Status

**Complete**

Phase 3 added Windows endpoint telemetry and three validated endpoint-focused detections.

## Detection 1 — Suspicious PowerShell Execution

**Data source:** Sysmon Event ID 1 — Process Create

**Script:**
`scripts/detect_suspicious_powershell.ps1`

**Core logic:**
- focus on `powershell.exe` and `pwsh.exe`
- inspect command lines
- identify indicators such as:
  - encoded commands
  - ExecutionPolicy Bypass
  - hidden-window execution
  - Invoke-Expression / IEX
  - DownloadString
  - Invoke-WebRequest

**Validation:**
- benign positive test succeeded
- 1-minute lookback succeeded
- detector self-alert was identified and tuned out
- validation evidence committed

**ATT&CK:**
- T1059.001 — Command and Scripting Interpreter: PowerShell

## Detection 2 — Suspicious Parent/Child Process Relationship

**Data source:** Sysmon Event ID 1 — Process Create

**Script:**
`scripts/detect_suspicious_parent_child.ps1`

**Core logic:**
- monitor Office-style parents:
  - winword.exe
  - excel.exe
  - powerpnt.exe
  - outlook.exe
  - onenote.exe
- alert when they launch selected scripting interpreters or LOLBins

**Validation:**
- live negative control succeeded
- safe synthetic `WINWORD.EXE -> powershell.exe` positive test succeeded
- evidence committed

**ATT&CK context:**
- T1059 — Command and Scripting Interpreter
- T1218 — System Binary Proxy Execution, when applicable to the observed child process

## Detection 3 — Privileged Local Group Membership Change

**Data source:** Windows Security Event ID 4732

**Script:**
`scripts/detect_admin_group_addition.ps1`

**Core logic:**
- inspect local-group membership additions
- alert when the target group is `Administrators`
- capture actor, member name, SID, host, and timestamp

**Validation:**
- live 30-minute negative control succeeded
- safe synthetic positive test succeeded
- evidence committed

**ATT&CK:**
- T1098 — Account Manipulation

## Detection Engineering Lessons

Phase 3 demonstrated several practical lessons:

- a correct rule can still generate a false positive
- detectors need tuning and exclusions
- lookback windows matter
- parent/child context is often more useful than a process name alone
- process, DNS, and network telemetry can be correlated with ProcessGuid and ProcessId
- safe synthetic validation can test rule logic without making unnecessary risky system changes
- ATT&CK mappings should describe the observed behavior rather than being applied mechanically

## Acceptance Criteria Review

- At least three endpoint detections tested: **complete**
- Detection logic committed: **complete**
- Validation evidence committed: **complete**
- ATT&CK mappings documented: **complete**
- False-positive and tuning considerations documented: **complete**

## Next Phase

Phase 4 will use these alerts as investigation starting points.

The objective is to move from:

```text
Alert -> Detection
```

to:

```text
Alert -> Triage -> Timeline -> Correlation -> Scope -> Disposition -> Remediation
```
