# Authentication Log Automation and Enrichment

## Objective

Automate repetitive SSH authentication triage by converting raw log lines into a readable investigation summary.

## Script

`scripts/analyze_auth_logs.py`

## Inputs

The script accepts an SSH authentication log file that contains password authentication records in the format used by the lab.

Examples:

```bash
python3 scripts/analyze_auth_logs.py data/sample-logs/auth.log
```

```bash
python3 scripts/analyze_auth_logs.py data/sample-logs/password_spray.log
```

The password-spray threshold can be adjusted:

```bash
python3 scripts/analyze_auth_logs.py data/sample-logs/password_spray.log --spray-threshold 4
```

The failed-then-success correlation window can also be changed:

```bash
python3 scripts/analyze_auth_logs.py data/sample-logs/auth.log --success-window-minutes 5
```

## Fields Extracted

For supported SSH password events, the script extracts:

- timestamp
- host
- username
- source IP
- source port
- authentication result
- invalid-user status
- normalized event type

## Automated Summary

The report includes:

- total parsed events
- failed authentication count
- successful authentication count
- configured failed-then-success time window
- hosts observed
- users observed
- source IP addresses
- event timeline
- investigation indicators

## Enrichment Logic

Source IPs are classified locally without external lookups.

Current classifications include:

- documentation/test ranges
- RFC1918 private ranges
- loopback
- link-local
- multicast
- public

The lab's synthetic addresses such as `192.0.2.0/24` and `198.51.100.0/24` are explicitly identified as documentation/test ranges.

## Investigation Indicators

### Possible Password Spray

Triggered when one source IP produces failed authentication attempts against at least the configured number of unique usernames.

### Failed-Then-Success Pattern

The analyzer now validates both **event order** and **elapsed time**.

A failed-then-success indicator is generated only when:

1. the failed and successful authentication events use the same source IP
2. the failure occurred before the success
3. the success occurred within the configured `--success-window-minutes` interval

The default window is 10 minutes.

The report includes the number of qualifying failures and the elapsed time between the first qualifying failure and the successful login.

These indicators are triage signals and do not prove malicious activity.

## Assumptions

- the input uses the lab's OpenSSH password-event format
- syslog timestamps do not include a year, so the analyzer assigns a fixed internal year only for relative event-order calculations
- the current sample data is expected to belong to a single chronological logging period
- the script only parses supported `Failed password` and `Accepted password` records
- public-IP enrichment is classification only; it does not contact reputation services

## Limitations

The current version does not:

- parse every possible OpenSSH message type
- perform threat-intelligence API lookups
- infer a real year or timezone from syslog timestamps
- safely correlate across a Dec. 31 -> Jan. 1 year boundary without additional date context
- correlate across multiple hosts automatically
- determine whether a login was truly malicious
- replace analyst review

## SOC Use Case

Instead of manually reading each authentication line, an analyst can run one command and immediately receive:

```text
raw authentication logs
        |
        v
field extraction
        |
        v
event summary
        |
        v
source-IP enrichment
        |
        v
time-window correlation
        |
        v
investigation indicators
```

This reduces repetitive triage work while keeping the analyst responsible for final interpretation.
