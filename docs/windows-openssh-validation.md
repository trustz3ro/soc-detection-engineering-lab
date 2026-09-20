# Windows OpenSSH Authentication Validation

## Objective

Validate password-spraying detection logic against native Windows OpenSSH telemetry.

## Environment

- Windows ThinkPad host
- Windows OpenSSH Server
- `OpenSSH/Operational` event log
- PowerShell
- Tailscale connectivity between lab systems

## Controlled Test

Failed SSH authentication attempts were generated from the Mac mini against three invalid usernames on the Windows ThinkPad:

- `fakeuser`
- `admin`
- `support`

All three attempts originated from:

`100.127.218.101`

## Native Windows OpenSSH Events

Observed messages included:

```text
sshd: Invalid user fakeuser from 100.127.218.101 port 62784
sshd: Invalid user admin from 100.127.218.101 port 62844
sshd: Invalid user support from 100.127.218.101 port 62874
```

The Windows Security log also recorded Event ID 4625 failures, but those events did not consistently preserve the failed username or source network address for these OpenSSH attempts. For this lab, the `OpenSSH/Operational` channel provides the richer source data for SSH-focused detection.

## Detection Script

`scripts/detect_windows_ssh_spray.ps1`

The script:

1. reads `OpenSSH/Operational`
2. finds `Invalid user` messages
3. extracts username and source IP
4. groups events by source IP
5. counts unique usernames
6. alerts when one source targets at least three unique usernames

## Expected Test Result

```text
ALERT: Possible password spraying detected.
Source IP: 100.127.218.101
Failed login attempts: 3
Unique usernames targeted: 3
Usernames: admin, fakeuser, support
```

## Security Relevance

This pattern can indicate password spraying, username enumeration, or early brute-force activity. Analysts should correlate the source address, timing, targeted accounts, allowlists, authorized testing windows, and surrounding authentication activity before escalation.

## Next Steps

- add a rolling time window
- add configurable thresholds and exclusions
- correlate OpenSSH events with Windows Security Event IDs 4624 and 4625
- add Sysmon telemetry
- forward Windows and Linux events to a SIEM
