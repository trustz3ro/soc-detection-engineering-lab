# Incident Investigation 002 — Privileged Local Group Membership Change

## Scenario

A detection reports that an account was added to the local Windows Administrators group.

The investigation objective is to determine:

- who performed the change
- which account was added
- whether the account is actually present in the Administrators group
- whether a real Event ID 4732 exists
- whether surrounding authentication activity supports a real privilege change
- whether the alert should be treated as malicious, benign, or synthetic test activity

## Safety Approach

This investigation intentionally avoids making a real privileged-group change.

The positive alert is generated using the detector's safe `-TestMode`, which simulates an Event ID 4732-style record through the same detection logic.

The investigation then verifies the real endpoint state and Security logs.

## Primary Evidence Sources

- Detector output from `detect_admin_group_addition.ps1 -TestMode`
- Windows Security Event ID 4732
- Windows Security Event IDs 4624 and 4625
- Current local Administrators group membership

## Investigation Helper

`scripts/collect_admin_group_investigation.ps1`

The helper:

1. enumerates current local Administrators membership
2. searches for recent Event ID 4732 records
3. reviews recent successful and failed logons
4. provides endpoint context for the alert

## Planned Workflow

1. Run the synthetic privileged-group detector.
2. Record the actor, member, host, and target group.
3. Collect current Administrators membership.
4. Search for real Event ID 4732 records.
5. Review nearby 4624/4625 authentication activity.
6. Compare the alert with actual endpoint state.
7. Determine scope and disposition.
8. Document remediation and lessons learned.

## Expected Outcome

Because the alert is intentionally synthetic and no real group membership is changed, the likely disposition is:

```text
Benign Positive / Synthetic Test
```

The important analyst task is proving that conclusion from endpoint evidence rather than assuming it.
