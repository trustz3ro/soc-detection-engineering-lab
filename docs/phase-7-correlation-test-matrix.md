# Phase 7 OpenSSH correlation validation

Validated October 11, 2026, America/Chicago.
Evidence timestamps use UTC and extend into October 12.

## Detection

Rule 100100 identifies individual Windows OpenSSH invalid-user events.
A Python correlator groups those events by target agent and source IP,
counts distinct usernames within the last 300 seconds, and emits JSON
when at least three usernames qualify.

Wazuh reads /var/log/openssh-correlation.json and generates rule 100110
at level 10. The correlated alert belongs to manager agent 000;
data.target_agent_id and data.target_agent_name identify the target.

These were controlled invalid-username attempts without submitted
passwords, not validated password guessing.

## Results

| Case | Expected | Observed | Validation |
|---|---|---|---|
| Three distinct usernames, same source, within five minutes | Alert | Rule 100110, three users, three attempts | Live pass |
| Repeated username | No output | Three individual events, no correlation output | Live pass |
| Alternating two usernames | No output | Four individual events, no correlation output | Live pass |
| Multiple sources | No output | Two usernames from Mac mini, one from MacBook Air | Live pass |
| Outside window | No output | Third username arrived 347 seconds after first | Live pass |

Nine automated tests also passed, covering agent separation,
the inclusive 300-second boundary, future-event exclusion,
and Wazuh timestamp formatting.

## Evidence

- [Correlated alert](evidence/phase-7-correlated-alert.json)
- [Repeated username](evidence/phase-7-repeated-user-events.jsonl)
- [Alternating two usernames](evidence/phase-7-two-user-events.jsonl)
- [Multiple sources](evidence/phase-7-multiple-source-events.jsonl)
- [Outside window](evidence/phase-7-outside-window-events.jsonl)

## Current limitations

Execution is manual. Repeated runs may emit duplicate results.
The script currently reads only the current alerts.json file, so a
five-minute window spanning daily rotation can miss earlier events.
Automatic execution, duplicate suppression, and rollover handling
remain pending.
