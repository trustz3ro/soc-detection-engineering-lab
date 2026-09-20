# Phase 7 Wazuh Validation Checklist

## 1. Platform Health

- [ ] Wazuh manager service running
- [ ] Wazuh indexer service running
- [ ] Wazuh dashboard accessible
- [ ] No critical startup errors
- [ ] Disk usage documented
- [ ] Memory usage documented

## 2. Windows Agent Onboarding

- [ ] Wazuh agent installed on ED_T14
- [ ] Agent appears as active in dashboard
- [ ] Hostname is correct
- [ ] Sysmon events visible
- [ ] Security events visible
- [ ] OpenSSH Operational events visible
- [ ] Timestamps are correct
- [ ] Usernames are correct
- [ ] Source IP fields are usable
- [ ] Process fields are usable

## 3. Linux Agent / Log Onboarding

- [ ] homelab-ubuntu appears in Wazuh
- [ ] /var/log/auth.log is ingested
- [ ] SSH failures are searchable
- [ ] successful SSH events are searchable
- [ ] username fields are usable
- [ ] source IP fields are usable
- [ ] timestamps are correct

## 4. Detection 1 — Windows OpenSSH Password Spray

Validation target:
- multiple failed SSH attempts
- one source IP
- multiple usernames

Known controlled pattern:
- source: Mac mini
- usernames: fakeuser, admin, support

Success criteria:
- [ ] events visible in Wazuh
- [ ] rule/query identifies multi-user failed-auth pattern
- [ ] source IP displayed
- [ ] targeted usernames recoverable
- [ ] alert severity documented
- [ ] false-positive notes documented

## 5. Detection 2 — Suspicious PowerShell

Validation target:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-LAB-TEST'"
```

Success criteria:
- [ ] Sysmon Event ID 1 visible
- [ ] command line preserved
- [ ] user preserved
- [ ] parent process preserved
- [ ] Wazuh rule/query matches ExecutionPolicy Bypass
- [ ] alert generated
- [ ] false-positive tuning documented

## 6. Detection 3 — Privileged Group Change

Validation target:
- Security Event ID 4732

Preferred validation:
- use safe evidence or controlled change process
- avoid unnecessary real privilege modification

Success criteria:
- [ ] Event ID 4732 searchable
- [ ] actor account visible
- [ ] member account visible
- [ ] target group visible
- [ ] rule/query matches Administrators-group addition
- [ ] alert generated
- [ ] synthetic-vs-real validation method documented

## 7. Dashboard Validation

Required panels:
- [ ] failed authentication count
- [ ] successful authentication count
- [ ] top source IPs
- [ ] top targeted usernames
- [ ] PowerShell process activity
- [ ] privileged group changes
- [ ] Windows vs Linux event volume

## 8. Evidence Capture

For each test:
- [ ] timestamp
- [ ] hostname
- [ ] source IP
- [ ] user/account
- [ ] event ID / source
- [ ] matching rule/query
- [ ] alert screenshot
- [ ] dashboard screenshot
- [ ] analyst interpretation
- [ ] disposition
- [ ] limitations / tuning note

## 9. Phase 7 Completion

- [ ] Windows and Linux telemetry searchable centrally
- [ ] 3 SIEM-native detections validated
- [ ] 1 dashboard complete
- [ ] setup documentation committed
- [ ] evidence committed
- [ ] Phase 1 centralized logging gap closed
