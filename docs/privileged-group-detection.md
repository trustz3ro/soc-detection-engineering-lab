# Privileged Local Group Membership Detection

## Objective

Detect when an account is added to the local Windows **Administrators** group.

## Data Source

Windows Security event log.

Primary event:

- **Event ID 4732 — A member was added to a security-enabled local group**

For this lab, the detector focuses on additions to:

```text
BUILTIN\Administrators
```

## Detection Script

`scripts/detect_admin_group_addition.ps1`

The script reviews Event ID 4732 and extracts:

- actor / subject account
- member name
- member SID
- target group
- computer
- timestamp

It alerts when the target group is `Administrators`.

## Why This Matters

Adding an account to the local Administrators group can grant broad control over a Windows endpoint.

Legitimate causes include:

- helpdesk work
- endpoint provisioning
- software deployment
- approved administrative access

Security-relevant causes can include:

- privilege escalation
- persistence
- unauthorized account changes
- compromised administrator activity

The event must therefore be investigated in context.

## Safe Validation

The detector supports:

```powershell
-TestMode
```

Test mode feeds a synthetic Event ID 4732-style record through the same matching logic without changing any real Windows group memberships.

## Live Validation

Live mode reads the Security event log:

```powershell
.\scripts\detect_admin_group_addition.ps1 -LookbackMinutes 30
```

If no additions occurred during the window, the expected result is:

```text
No additions to the local Administrators group detected in the last 30 minutes.
```

## Investigation Questions

When this alert fires, determine:

- Who performed the change?
- Which account was added?
- Was the account expected to receive admin rights?
- Was there a ticket or approved maintenance window?
- What did the new administrator account do afterward?
- Did suspicious process, logon, DNS, or network activity occur nearby?

## MITRE ATT&CK

Relevant mapping:

- **T1098 — Account Manipulation**

Depending on the broader behavior, additional privilege-escalation or persistence techniques may also apply.

## False Positives and Tuning

Potential false positives:

- approved helpdesk activity
- new device provisioning
- endpoint management tools
- software installation workflows
- temporary administrative access

Useful tuning fields:

- actor account
- added account
- host
- time of day
- approved administrative accounts
- change-ticket reference


## Validation Result

The detector passed both the live negative-control test and the safe synthetic positive test.

Negative control:

```text
No additions to the local Administrators group detected in the last 30 minutes.
```

Synthetic positive test:

```text
ALERT: Account added to privileged local group.
Actor: Ed_T14\\ej975
MemberName: LAB\\testuser
TargetGroup: Builtin\\Administrators
ValidationMode: Synthetic
```

This confirms the rule correctly identifies a simulated Event ID 4732 addition to the local Administrators group.
