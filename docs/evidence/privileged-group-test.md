# Privileged Local Group Membership Detection — Validation Evidence

## Negative Control

The detector was run against the Windows Security event log with a 30-minute lookback:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\detect_admin_group_addition.ps1" -LookbackMinutes 30
```

Observed result:

```text
No additions to the local Administrators group detected in the last 30 minutes.
```

This established a clean baseline before positive testing.

## Synthetic Positive Test

The detector was then run in safe synthetic validation mode:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\detect_admin_group_addition.ps1" -TestMode
```

Observed result:

```text
ALERT: Account added to privileged local group.
Time: 09/19/2026 19:48:37
EventId: 4732
Computer: ED_T14
Actor: Ed_T14\\ej975
MemberName: LAB\\testuser
MemberSid: S-1-5-21-111111111-222222222-333333333-1001
TargetGroup: Builtin\\Administrators
ValidationMode: Synthetic
```

## Validation Outcome

The rule correctly identified a simulated Event ID 4732 addition to the local Administrators group.

The validation confirmed:

- live negative control works
- synthetic positive test works
- actor and target account fields are extracted
- target privileged group is identified
- validation mode is clearly labeled

## Why Synthetic Validation Was Used

The goal was to validate the detection without making an unnecessary real change to local administrator membership.

The synthetic record is passed through the same matching logic used for live Event ID 4732 records.

## Status

Detection #3 for Phase 3: **Validated**

Data source:

- Windows Security Event ID 4732

MITRE ATT&CK:

- T1098 — Account Manipulation
