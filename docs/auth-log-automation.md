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

The script currently flags:

### Possible Password Spray

Triggered when one source IP produces failed authentication attempts against at least the configured number of unique usernames.

### Failed-Then-Success Pattern

Triggered when the same source IP has both failed authentication events and a later successful authentication represented in the input data.

These indicators are triage signals and do not prove malicious activity.

## Assumptions

- the input uses the lab's OpenSSH password-event format
- events are already in chronological order
- the script does not currently normalize year or timezone
- the script only parses supported `Failed password` and `Accepted password` records
- public-IP enrichment is classification only; it does not contact reputation services

## Limitations

The current version does not:

- parse every possible OpenSSH message type
- perform threat-intelligence API lookups
- calculate precise rolling time windows
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
investigation indicators
```

This reduces repetitive triage work while keeping the analyst responsible for final interpretation.
