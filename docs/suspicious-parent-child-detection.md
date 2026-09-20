# Suspicious Parent/Child Process Detection

## Objective

Detect unusual process relationships where a Microsoft Office-style application launches a command or scripting interpreter.

Examples:

```text
winword.exe -> powershell.exe
excel.exe   -> cmd.exe
outlook.exe -> wscript.exe
```

## Data Source

`Microsoft-Windows-Sysmon/Operational`

Event:

`Sysmon Event ID 1 — Process Create`

## Detection Script

`scripts/detect_suspicious_parent_child.ps1`

The detector compares:

- ParentImage
- Image
- ParentCommandLine
- CommandLine
- User
- ProcessGuid

## Why This Matters

Office applications launching script interpreters or living-off-the-land binaries can be associated with malicious document execution, phishing, macro abuse, or post-exploitation activity.

The relationship alone is not proof of compromise. Legitimate add-ins, automation, or administrative tooling can create similar process chains.

## Monitored Office Parents

- winword.exe
- excel.exe
- powerpnt.exe
- outlook.exe
- onenote.exe

## Monitored Child Processes

- powershell.exe
- pwsh.exe
- cmd.exe
- wscript.exe
- cscript.exe
- mshta.exe
- rundll32.exe
- regsvr32.exe

## Validation Strategy

For safety and reproducibility, the first test should validate the detection logic against a controlled synthetic Sysmon-like event or a benign locally generated process relationship. Do not use an actual malicious document.

## MITRE ATT&CK

Primary behavioral mappings depend on the child process and execution mechanism. Commonly relevant techniques include:

- T1059 — Command and Scripting Interpreter
- T1218 — System Binary Proxy Execution

ATT&CK mappings should be applied to the specific observed behavior, not just the parent/child relationship.

## Tuning Considerations

Potential false positives:

- Office add-ins
- enterprise automation
- software deployment
- approved macros or scripts
- helpdesk tooling

Useful tuning fields:

- ParentImage
- ParentCommandLine
- Image
- CommandLine
- signer
- hash
- user
- host
- time of day


## Validation Result

The detector passed both a negative-control test and a safe synthetic positive test.

Negative control:

```text
No suspicious Office parent/child process activity detected in the last 15 minutes.
```

Synthetic positive test:

```text
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ValidationMode: Synthetic
```

The rule correctly alerted on the simulated `WINWORD.EXE -> powershell.exe` relationship.
