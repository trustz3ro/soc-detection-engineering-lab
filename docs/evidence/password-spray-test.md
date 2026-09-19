# Password Spray Detection Test Evidence

## Test Date

2026-09-19

## Environment

- Host platform: Mac mini
- Virtualization/container platform: OrbStack
- Guest OS: Ubuntu 26.04.1 LTS
- Repository: `soc-detection-engineering-lab`

## Command

```bash
python3 scripts/detect_password_spray.py
```

## Observed Output

```text
ALERT: Possible password spraying detected.
Source IP: 198.51.100.25
Unique usernames targeted: 5
Usernames: admin, edwardjohnson, guest, root, support
```

## Result

The detection executed successfully against the synthetic SSH authentication log and identified a password-spraying pattern originating from one source IP against five unique usernames.

## Notes

This evidence validates the current prototype logic. The next validation steps are to test against native Linux authentication logs and equivalent Windows authentication telemetry, then capture screenshots for the portfolio.
