# Native Linux Authentication Validation

## Objective

Validate the password-spraying detection against real Ubuntu SSH authentication telemetry from `/var/log/auth.log`, rather than only synthetic sample data.

## Environment

- Ubuntu 26.04.1 LTS
- OpenSSH Server
- OrbStack-hosted Ubuntu VM
- Mac mini host
- Python 3

## Test Procedure

OpenSSH Server was installed and enabled inside the Ubuntu lab. Controlled failed SSH authentication attempts were then generated from the host against several invalid usernames.

Targeted usernames:

- `fakeuser`
- `admin`
- `support`

The resulting native SSH events were written to `/var/log/auth.log`.

## Example Native Log Pattern

```text
Failed password for invalid user fakeuser from 192.168.139.3 ...
Failed password for invalid user admin from 192.168.139.3 ...
Failed password for invalid user support from 192.168.139.3 ...
```

## Detection Script

`scripts/detect_linux_auth.py`

The script reads `/var/log/auth.log`, extracts usernames and source IPs from failed SSH authentication events, groups activity by source IP, and alerts when a source targets at least three unique usernames.

## Validated Result

```text
ALERT: Possible password spraying detected.
Source IP: 192.168.139.3
Failed login attempts: 9
Unique usernames targeted: 3
Usernames: admin, fakeuser, support
```

## Outcome

The detection successfully identified the controlled password-spraying pattern in genuine Linux SSH authentication telemetry.

This extends the project beyond synthetic-log testing and demonstrates detection logic operating against native operating-system authentication data.

## Next Steps

- add a rolling time window to reduce false positives
- add configurable thresholds
- support IPv6
- validate Windows authentication telemetry
- ingest telemetry into a SIEM
- preserve screenshot evidence in the portfolio
