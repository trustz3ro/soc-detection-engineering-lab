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
- Initiated
- User
- ProcessId / ProcessGuid

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

## Event ID 3 Validation — Network Connection Test

A controlled connectivity test was run with:

```powershell
Test-NetConnection github.com -Port 443
```

The connectivity test succeeded:

```text
RemoteAddress: 140.82.114.4
RemotePort: 443
SourceAddress: 192.168.4.20
TcpTestSucceeded: True
```

Sysmon Event ID 3 records were then reviewed.

### What We Observed

The newest events included DNS and local discovery traffic, including:

- `svchost.exe` using UDP/53 to communicate with DNS resolvers such as `1.1.1.1` and `1.0.0.1`
- `brave.exe` and `svchost.exe` generating multicast DNS traffic on UDP/5353
- both IPv4 and IPv6 network events

Example fields:

```text
Image: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\NETWORK SERVICE
Protocol: udp
SourceIp: 192.168.4.20
DestinationIp: 1.1.1.1
DestinationPort: 53
```

### Important Lesson

The first 10 Event ID 3 records did **not necessarily show the exact GitHub TCP/443 connection** even though the connection test succeeded.

This is normal in a busy endpoint log. Other network events can occur immediately before or after the test and push the specific event outside a small `-MaxEvents` result set.

SOC analysts often filter by:

- destination IP
- destination port
- process image
- process ID
- timestamp

instead of only looking at the newest events.

### Field Meanings

- **Image** — process responsible for the connection
- **User** — account context for that process
- **Protocol** — TCP or UDP
- **Initiated** — whether the process initiated the connection
- **SourceIp / SourcePort** — local endpoint
- **DestinationIp / DestinationPort** — remote endpoint
- **ProcessGuid** — stable Sysmon identifier useful for correlating with Event ID 1

### Why Event ID 3 Matters

Event ID 3 lets an analyst connect process activity to network behavior.

For example:

```text
powershell.exe
    -> network connection
        -> external IP on TCP/443
```

That relationship can become important during malware, command-and-control, download, or data-exfiltration investigations.

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
7. Generate network activity.
8. Validate and review Sysmon Event ID 3.

Next:

9. Filter Event ID 3 to isolate the GitHub TCP/443 connection.
10. Generate and review a DNS query.
11. Validate Sysmon Event ID 22.
12. Build a detection around suspicious PowerShell activity.


## Event ID 3 Follow-Up — Isolating the GitHub HTTPS Connection

Filtering the network telemetry by destination IP and destination port successfully isolated the exact connection created by:

```powershell
Test-NetConnection github.com -Port 443
```

Observed Sysmon Event ID 3 fields:

```text
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: Ed_T14\ej975
Protocol: tcp
Initiated: true
SourceIp: 192.168.4.20
SourcePort: 63309
DestinationIp: 140.82.114.4
DestinationPort: 443
DestinationPortName: https
```

### Why This Matters

This event ties together three important pieces of evidence:

1. **Process** — PowerShell made the connection.
2. **User** — the connection ran in the `Ed_T14\ej975` context.
3. **Network destination** — the process connected to `140.82.114.4` over TCP/443.

This is the type of correlation a SOC analyst uses during investigations.

For example:

```text
Process Creation (Event ID 1)
        |
        v
powershell.exe
        |
        v
Network Connection (Event ID 3)
        |
        v
140.82.114.4:443
```

The same filtered results also showed other legitimate HTTPS activity from Brave, Git, Microsoft Defender, and Windows applications. This demonstrates why analysts should avoid treating port 443 by itself as suspicious. The process, user, destination, timing, and surrounding activity all matter.


## Event ID 22 Validation — DNS Query Telemetry

Sysmon Event ID 22 successfully captured DNS activity on the Windows endpoint.

Observed fields included:

```text
QueryName: settings-win.data.microsoft.com
QueryStatus: 0
Image: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\SYSTEM
```

Other examples included DNS activity from:

- `OneDrive.exe`
- `brave.exe`
- `gamingservices.exe`
- `Sysmon64.exe`

### Important Fields

- **QueryName** — domain name or reverse-DNS name being queried
- **QueryStatus** — result status for the DNS request
- **QueryResults** — returned CNAME, IPv4, IPv6, or PTR data when available
- **Image** — process associated with the DNS query
- **User** — account context for the querying process
- **ProcessGuid / ProcessId** — identifiers used for correlation with other Sysmon events

### QueryStatus

A value of:

```text
QueryStatus: 0
```

indicates the query completed successfully.

Some observed reverse-DNS lookups returned:

```text
QueryStatus: 9003
QueryResults: -
```

which means the requested DNS name did not exist.

### Reverse DNS

Queries ending in:

```text
in-addr.arpa
```

are IPv4 reverse-DNS lookups.

Queries ending in:

```text
ip6.arpa
```

are IPv6 reverse-DNS lookups.

These attempt to map an IP address back to a hostname.

### Why Event ID 22 Matters

DNS telemetry is valuable because many network connections begin with name resolution.

A useful investigation chain can look like:

```text
Process Creation — Event ID 1
        |
        v
powershell.exe
        |
        v
DNS Query — Event ID 22
        |
        v
example.com
        |
        v
Network Connection — Event ID 3
        |
        v
remote IP:443
```

This lets an analyst connect **process execution**, **domain resolution**, and **network activity** into one timeline.

### SOC Lesson

A single endpoint generates a large amount of legitimate DNS traffic. A domain name by itself is not enough to determine whether an event is malicious.

Analysts should consider:

- which process made the request
- which user ran the process
- whether the domain is expected
- whether the process later connected to the resolved address
- timing and frequency
- surrounding endpoint activity


## Event ID 22 Follow-Up — Isolating the GitHub DNS Lookup

Filtering Sysmon Event ID 22 by `QueryName: github.com` successfully isolated the DNS activity associated with the earlier PowerShell connectivity test.

Observed PowerShell DNS event:

```text
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: Ed_T14\ej975
ProcessId: 14480
QueryName: github.com
QueryStatus: 0
QueryResults: ::ffff:140.82.114.4;
```

The same PowerShell process also resolved other GitHub addresses during the test, including:

```text
140.82.114.3
140.82.113.4
```

This is normal because a hostname may resolve to different addresses over time or across repeated queries.

The filtered results also showed Git's HTTPS helper resolving `github.com`:

```text
Image: C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe
QueryName: github.com
QueryResults: 140.82.112.3;
```

### Correlation Lesson

The PowerShell Event ID 22 used:

```text
ProcessGuid: {0c6a6533-257e-6aaf-5e07-000000005e00}
ProcessId: 14480
```

The earlier Event ID 3 GitHub HTTPS connection used the same ProcessGuid and ProcessId.

That allows the analyst to correlate:

```text
PowerShell
    -> DNS query for github.com
    -> resolved GitHub IP
    -> TCP/443 network connection
```

This is stronger evidence than looking at any one event by itself.

### Important Note

One `github.com` DNS event returned `QueryStatus: 1460` with no result, while other queries from the same process succeeded. A single failed or timed-out lookup should be interpreted in context rather than treated as malicious by itself.
