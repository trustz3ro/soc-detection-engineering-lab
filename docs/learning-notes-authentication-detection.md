# Learning Notes — Authentication Detection Lab

These notes explain what was built, why each step mattered, and what the observed results mean.

## 1. Lab Goal

The goal of this phase was to move from simple synthetic test data into real operating-system telemetry and prove that the same detection concept could work across Linux and Windows.

The detection concept was **password spraying**: one source attempts authentication against multiple usernames.

The workflow was:

1. generate controlled failed logins
2. inspect native operating-system logs
3. identify a reliable event pattern
4. parse the events
5. group activity by source IP
6. count unique usernames
7. trigger an alert when the threshold is reached
8. document and validate the result

---

## 2. Synthetic Detection First

We first tested the idea against synthetic SSH log data.

Files:

- `data/sample-logs/password_spray.log`
- `scripts/detect_password_spray.py`

The Python script grouped failed logins by source IP and tracked how many unique usernames each source attempted.

Why this mattered:

Synthetic data lets us test detection logic in a controlled environment before working with noisier real logs.

---

## 3. Linux Native Telemetry

### Environment

The Ubuntu lab runs inside OrbStack on the Mac mini.

OpenSSH Server was installed and enabled so the VM could generate real SSH authentication events.

Important commands:

```bash
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
systemctl status ssh --no-pager
```

### Native Linux Log Source

Ubuntu recorded SSH authentication activity in:

```text
/var/log/auth.log
```

We generated failed SSH attempts against several usernames and then inspected the log:

```bash
sudo tail -n 30 /var/log/auth.log
```

Observed pattern:

```text
Failed password for invalid user fakeuser from 192.168.139.3 ...
Failed password for invalid user admin from 192.168.139.3 ...
Failed password for invalid user support from 192.168.139.3 ...
```

### Linux Detector

File:

`scripts/detect_linux_auth.py`

The script:

- opens `/var/log/auth.log`
- looks for `Failed password`
- extracts username and source IP
- groups failures by source IP
- counts failed attempts
- counts unique usernames
- alerts when a source targets at least 3 usernames

Validated result:

```text
ALERT: Possible password spraying detected.
Source IP: 192.168.139.3
Failed login attempts: 9
Unique usernames targeted: 3
Usernames: admin, fakeuser, support
```

### Key Lesson

A detection is stronger when it is validated against the same telemetry that a real analyst would review.

---

## 4. Windows Security Event Logs

The ThinkPad already had Windows OpenSSH Server running.

Command:

```powershell
Get-Service sshd
```

Windows Security auditing showed:

- Event ID `4625` = failed logon
- Event ID `4624` = successful logon

Commands used:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 |
Format-List TimeCreated, Id, Message
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 10 |
Format-List TimeCreated, Id, Message
```

### Important Finding

For the SSH failures we generated, Event ID 4625 did not consistently preserve the failed username and source IP.

That made the generic Security log less useful for this specific SSH detection.

This is an important SOC lesson: **the best log source depends on the behavior you are detecting.**

---

## 5. Windows OpenSSH Operational Log

We checked available OpenSSH logs:

```powershell
Get-WinEvent -ListLog *OpenSSH*
```

Useful channel:

```text
OpenSSH/Operational
```

Command:

```powershell
Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 30 |
Format-List TimeCreated, Id, Message
```

This channel preserved the exact SSH details we needed.

Observed failures:

```text
sshd: Invalid user fakeuser from 100.127.218.101 ...
sshd: Invalid user admin from 100.127.218.101 ...
sshd: Invalid user support from 100.127.218.101 ...
```

It also recorded successful public-key logins.

That makes `OpenSSH/Operational` a better source for SSH-focused detection on this Windows host.

---

## 6. Windows Password-Spray Detector

File:

`scripts/detect_windows_ssh_spray.ps1`

The PowerShell detector:

- reads `OpenSSH/Operational`
- matches `Invalid user` events
- extracts username and source IP
- groups events by source IP
- counts attempts
- counts unique usernames
- triggers an alert at 3 unique usernames

The script was executed with a one-time PowerShell execution-policy bypass:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\scripts\detect_windows_ssh_spray.ps1"
```

This did not permanently change the system execution policy.

Validated result:

```text
ALERT: Possible password spraying detected.
Source IP: 100.127.218.101
Failed login attempts: 3
Unique usernames targeted: 3
Usernames: admin, fakeuser, support
```

---

## 7. What We Proved

We validated the same detection concept on two operating systems:

### Linux

Source:
`/var/log/auth.log`

Detector:
Python

### Windows

Source:
`OpenSSH/Operational`

Detector:
PowerShell

This demonstrates cross-platform detection engineering rather than a single hard-coded example.

---

## 8. Core SOC Concepts Practiced

### Telemetry

Telemetry is the event data produced by systems and applications.

Examples in this lab:

- Linux SSH authentication logs
- Windows Security events
- Windows OpenSSH Operational events

### Detection Logic

Detection logic converts raw events into a meaningful security condition.

Example:

> Alert when one source IP targets 3 or more unique usernames.

### Threshold

A threshold is the value at which normal activity becomes suspicious enough to alert.

Current lab threshold:

```text
3 unique usernames
```

### False Positive

A false positive is activity that matches the detection but is not malicious.

Examples:

- authorized penetration test
- account-validation script
- misconfigured automation
- vulnerability scanner

### Correlation

Correlation means combining multiple events or data sources to understand the full story.

Future example:

- OpenSSH failed logins
- Windows 4625 events
- Windows 4624 success
- Sysmon process activity
- SIEM timeline

---

## 9. Why the Detection Matters

Password spraying often attempts a small number of passwords across multiple accounts.

A SOC analyst would want to know:

- which source IP generated the attempts
- which accounts were targeted
- how many attempts occurred
- whether any login eventually succeeded
- whether the source was expected
- whether the behavior occurred within a short time window
- whether the affected account later performed suspicious activity

---

## 10. Current Project Progress

Completed:

- synthetic SSH authentication detection
- failed-login-then-success detection
- password-spray detection
- Linux native authentication validation
- Windows Security log review
- Windows OpenSSH Operational log review
- Windows native OpenSSH detection
- cross-platform validation
- GitHub documentation and evidence

Next:

1. Sysmon installation and validation
2. process creation telemetry
3. suspicious PowerShell detection
4. Windows + Linux log forwarding
5. SIEM ingestion
6. alert queries
7. incident investigation workflow
8. enrichment and automation

---

## 11. Interview Explanation

A concise way to explain this project:

> I built a cross-platform authentication detection lab. I started with synthetic SSH logs to test the detection logic, then validated the same password-spraying behavior against real Ubuntu auth logs and Windows OpenSSH event logs. I wrote a Python detector for Linux and a PowerShell detector for Windows that group failed logins by source IP, count unique usernames, and alert when a threshold is reached. I also documented false-positive considerations and validation evidence in GitHub.

---

## 12. What to Review Later

Focus on understanding these ideas:

- difference between raw logs and detections
- why source selection matters
- how regex extracts fields
- why grouping by source IP is useful
- why unique usernames matter for password spraying
- why thresholds need tuning
- why time windows reduce false positives
- why cross-platform validation strengthens a detection
- how an analyst would investigate the alert after it fires
