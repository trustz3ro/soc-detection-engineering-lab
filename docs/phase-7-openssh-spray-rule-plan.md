# Phase 7: Windows OpenSSH Spray Rule Plan

## Detection contract

Alert when one source IP generates invalid-user OpenSSH events for at least
three distinct usernames within five minutes on ED_T14.

Source channel: OpenSSH/Operational.
Observed message: sshd: Invalid user <username> from <source_ip> port <port>

The existing PowerShell detector groups by source IP and counts unique
usernames across all available events. The five-minute window is a proposed
SIEM improvement and must be validated.

## Fields required in Wazuh

- Windows agent and host name
- Event timestamp and OpenSSH/Operational channel
- Source IP extracted from the message
- Targeted username extracted from the message

Use the actual ingested event to confirm field names before writing XML.
Correlate on the same source IP and different usernames. Keep correlation
scoped to the Windows agent unless cross-host behavior is explicitly desired.

## Validation cases

1. Three users from one IP within five minutes: alert.
2. Three failures for one user from one IP: no spray alert.
3. Three users from different IPs: no spray alert.
4. Three users from one IP outside five minutes: no spray alert.
5. Known controlled test: fakeuser, admin, support from 100.127.218.101.

Record the matching event fields, rule ID, alert severity, screenshot,
false-positive considerations, and analyst disposition in the evidence
template. Do not mark the rule validated until Wazuh logtest and live
agent events both confirm these cases.
