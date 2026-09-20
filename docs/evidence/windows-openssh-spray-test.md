# Windows OpenSSH Password-Spray Validation Evidence

## Test Result

The Windows OpenSSH password-spray detector was executed successfully on the ThinkPad against native `OpenSSH/Operational` telemetry.

## Command

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\detect_windows_ssh_spray.ps1"
```

## Observed Output

```text
ALERT: Possible password spraying detected.
Source IP: 100.127.218.101
Failed login attempts: 3
Unique usernames targeted: 3
Usernames: admin, fakeuser, support
```

## Validation Outcome

The detector correctly grouped failed SSH authentication events by source IP, counted unique targeted usernames, and generated an alert at the configured threshold.

This validates the password-spraying detection against native Windows OpenSSH telemetry.

## Notes

PowerShell script execution was blocked by the system execution policy, so the test was run with a one-time process-level bypass rather than changing the machine's persistent policy.

## Next Steps

- add time-window logic
- correlate with Windows Security Event IDs 4624 and 4625
- add Sysmon telemetry
- forward Windows and Linux logs to a SIEM
