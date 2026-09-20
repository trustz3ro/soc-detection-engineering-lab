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

Source-IP enrichment can be included in the same investigation run:

```bash
python3 scripts/analyze_auth_logs.py data/sample-logs/auth.log --enrich-sources
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
- optional source-IP enrichment
- event timeline
- investigation indicators

## Integrated Enrichment

When `--enrich-sources` is enabled, the analyzer reuses `scripts/enrich_ioc.py` to add source-IP context directly to the authentication report.

The integrated output can include:

- documentation/test-range identification
- RFC1918 private-address identification
- public-address classification
- reverse-DNS hostname when available
- analyst-oriented context notes

This keeps the standalone IOC utility reusable while allowing authentication investigations to perform enrichment in a single command.

## Investigation Indicators

### Possible Password Spray

Triggered when one source IP produces failed authentication attempts against at least the configured number of unique usernames.

### Failed-Then-Success Pattern

The analyzer validates both event order and elapsed time.

A failed-then-success indicator is generated only when:

1. the failed and successful authentication events use the same source IP
2. the failure occurred before the success
3. the success occurred within the configured `--success-window-minutes` interval

The default window is 10 minutes.

## Assumptions and Limitations

- the input uses the lab's supported OpenSSH password-event format
- syslog timestamps do not include a year, so a fixed internal year is used only for relative ordering
- the script does not infer a real year or timezone
- reverse DNS is point-in-time context and may return no result
- the script does not perform commercial threat-intelligence lookups
- enrichment and indicators do not determine maliciousness
- analyst review remains required

## SOC Use Case

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
time-window correlation
        |
        v
optional IOC enrichment
        |
        v
investigation indicators
```

This reduces repetitive triage steps while preserving analyst judgment.
