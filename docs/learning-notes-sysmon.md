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

## Why Start Small

A very broad Sysmon configuration can generate large amounts of telemetry.

For learning, we are starting with three event types so each one can be understood and tested before adding more advanced coverage.

## Next Lab Steps

1. Install Sysmon with the lab configuration.
2. Verify the Sysmon service is running.
3. Confirm the Operational event log exists.
4. Generate a test process.
5. Review Event ID 1.
6. Generate a network event.
7. Review Event ID 3.
8. Generate a DNS query.
9. Review Event ID 22.
10. Build a detection around suspicious PowerShell activity.
