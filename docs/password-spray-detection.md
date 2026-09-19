# Authentication Detection: Password Spraying

## Objective

Detect a possible password-spraying pattern in SSH authentication logs by identifying one source IP that generates failed logins against several different usernames.

## Test Data

Synthetic SSH authentication events are stored in:

`data/sample-logs/password_spray.log`

The sample uses one source IP attempting authentication against multiple accounts.

## Detection Logic

The script:

`scripts/detect_password_spray.py`

performs the following steps:

1. Reads failed SSH authentication events.
2. Extracts the source IPv4 address.
3. Extracts the targeted username.
4. Groups usernames by source IP.
5. Counts unique usernames targeted by each source.
6. Generates an alert when a single source reaches the configured threshold.

The current threshold is four unique usernames.

## Example Result

```text
ALERT: Possible password spraying detected.
Source IP: 198.51.100.25
Unique usernames targeted: 5
Usernames: admin, edwardjohnson, guest, root, support
```

## MITRE ATT&CK Mapping

- **T1110 — Brute Force**
- **T1110.003 — Password Spraying**

Password spraying attempts a small number of passwords across many accounts to reduce the likelihood of account lockouts.

## False Positive Considerations

This pattern can also occur during authorized penetration testing, vulnerability assessments, account validation scripts, or misconfigured automation. Analysts should correlate with source ownership, timing, approved testing windows, targeted accounts, and other authentication telemetry before escalating.

## Future Improvements

- use a defined rolling time window
- track attempt count and unique usernames together
- support IPv6
- parse native Linux authentication logs
- add Windows Event Log equivalents
- emit JSON for SIEM ingestion
- add configurable thresholds and allowlists

## Lab Status

Working prototype created for the authentication-detection phase of the SOC Detection Engineering Lab.
