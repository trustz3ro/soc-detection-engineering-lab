# Learning Notes — Sysmon Setup

## What Sysmon Is

Sysmon (System Monitor) is a Windows system service and driver from Microsoft Sysinternals. Once installed, it records detailed endpoint activity into the Windows Event Log.

For this lab, Sysmon will give us richer endpoint telemetry than normal Windows Security auditing alone.

## Why We Are Adding It

Authentication logs tell us **who tried to log in**.

Sysmon helps us see **what happened on the endpoint**, including:

- process creation
- command lines
- network connections
- DNS queries
- parent/child process relationships
- file and registry activity when configured

This lets us move from authentication detection into endpoint detection and investigation.

## Initial Lab Configuration

File:

`configs/sysmon-lab.xml`

The first configuration intentionally keeps the scope small and understandable.

It enables:

- **Process Create** — Sysmon Event ID 1
- **Network Connect** — Sysmon Event ID 3
- **DNS Query** — Sysmon Event ID 22
- SHA256 hashing for process images

## Important Event IDs

### Event ID 1 — Process Creation

Shows a process starting.

Useful fields include:

- Image
- CommandLine
- ParentImage
- ParentCommandLine
- User
- ProcessId
- ProcessGuid
- IntegrityLevel
- Hashes

Example use case:

Detect or investigate suspicious PowerShell execution.

### Event ID 3 — Network Connection

Shows a process making a network connection.

Useful fields include:

- Image
- SourceIp
- SourcePort
- DestinationIp
- DestinationPort
- Protocol

Example use case:

See which process connected to an external system.

### Event ID 22 — DNS Query

Shows DNS lookups performed by processes.

Useful fields include:

- Image
- QueryName
- QueryStatus

Example use case:

Identify suspicious or unexpected domain lookups.

## Event ID 1 Validation — Notepad Test

A controlled process-creation test was performed by running:

```powershell
notepad.exe
```

Sysmon immediately generated Event ID 1 records.

Important observed fields included:

- **Image** — the executable that actually ran
- **CommandLine** — how the process was launched
- **CurrentDirectory** — the working directory at launch
- **User** — the account that started the process
- **IntegrityLevel** — the privilege level of the process
- **Hashes** — SHA256 hash of the executable
- **ParentImage** — the executable that launched the new process
- **ParentCommandLine** — how the parent process was started
- **ProcessId / ProcessGuid** — identifiers used to track and correlate the process

### Observed Notepad Process Chain

One event showed:

```text
CommandLine: "C:\Windows\system32\notepad.exe"
User: Ed_T14\ej975
IntegrityLevel: High
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This tells us that PowerShell launched Notepad.

A second Event ID 1 appeared almost immediately for the packaged Windows Notepad application, where the first Notepad process became the parent of another Notepad process.

That is a useful lesson: **one user action can produce multiple process-creation events**.

Analysts should follow parent/child relationships instead of assuming every process event represents a separate user action.

### Why Parent/Child Relationships Matter

Parent/child process relationships help answer questions such as:

- What launched this program?
- Was PowerShell involved?
- Did a browser launch a script interpreter?
- Did Office launch PowerShell or cmd.exe?
- Did one suspicious process spawn another?

A normal chain might look like:

```text
powershell.exe
    -> notepad.exe
```

A more suspicious chain could look like:

```text
winword.exe
    -> powershell.exe
        -> cmd.exe
```

The second example would deserve investigation because Office applications normally should not be spawning script interpreters without a clear reason.

## Why Start Small

A very broad Sysmon configuration can generate large amounts of telemetry.

For learning, we are starting with three event types so each one can be understood and tested before adding more advanced coverage.

## Current Progress

Completed:

1. Install Sysmon with the lab configuration.
2. Verify the Sysmon service is running.
3. Confirm the Operational event log exists.
4. Generate a controlled test process.
5. Validate Sysmon Event ID 1.
6. Review process image, command line, user, integrity, hash, and parent process fields.

Next:

7. Generate a network event.
8. Review Event ID 3.
9. Generate a DNS query.
10. Review Event ID 22.
11. Build a detection around suspicious PowerShell activity.
