# Detection Scenarios

## 1. Repeated Failed Logins
**Goal:** Identify password-spraying or brute-force-like behavior.

**Telemetry:** Windows Security logs, Linux authentication logs.

**Look for:** Multiple authentication failures from the same source, against the same account, or across several accounts within a short time window.

**MITRE ATT&CK:** T1110 - Brute Force.

## 2. Successful Login After Repeated Failures
**Goal:** Identify a possible account compromise following failed authentication attempts.

**Look for:** A burst of failed logins followed by a successful authentication for the same account or source.

## 3. Suspicious PowerShell Activity
**Goal:** Detect potentially malicious or unusual PowerShell execution.

**Telemetry:** PowerShell logging, Sysmon process creation, Windows Security logs.

**Look for:** Encoded commands, hidden windows, unusual parent processes, download behavior, or unexpected administrative commands.

**MITRE ATT&CK:** T1059.001 - PowerShell.

## 4. Privileged Group Membership Change
**Goal:** Detect privilege escalation or unauthorized administrative access.

**Look for:** Accounts added to local Administrators or other privileged groups.

## 5. Unusual Process Execution
**Goal:** Identify processes that are rare, unexpected, or launched from suspicious locations.

**Telemetry:** Sysmon process creation events.

## 6. Linux SSH Authentication Failures
**Goal:** Detect repeated failed SSH logins.

**Telemetry:** `/var/log/auth.log` or equivalent journal data.

## 7. Security-Relevant Account Changes
**Goal:** Track account creation, disablement, deletion, password changes, and privilege-related modifications.
