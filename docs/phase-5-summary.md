# Phase 5 Summary — Automation and Enrichment

## Status

**Complete**

Phase 5 focused on reducing repetitive SOC analysis tasks with reusable Python tooling.

## Authentication Log Analyzer

File:

`scripts/analyze_auth_logs.py`

Validated capabilities:

- parses supported OpenSSH password-authentication events
- extracts timestamp, host, username, source IP, source port, result, and normalized event type
- summarizes failed and successful authentication activity
- identifies password-spray patterns
- correlates failed authentications followed by a later success
- enforces a configurable failed-then-success time window
- calculates elapsed time for correlated activity
- optionally enriches source IPs during the same investigation run

### Validation Results

`auth.log`

- 4 parsed events
- 3 failures
- 1 successful login
- same source IP
- success occurred 13 seconds after the first qualifying failure
- failed-then-success indicator generated correctly

`password_spray.log`

- 5 parsed events
- 5 failed authentications
- 5 unique usernames
- same source IP
- password-spray indicator generated correctly
- no failed-then-success indicator because no success existed

## IOC Enrichment Utility

File:

`scripts/enrich_ioc.py`

Validated capabilities:

- accepts IPv4, IPv6, and domain indicators
- classifies documentation/test ranges
- classifies RFC1918 private space
- identifies other local/special address categories
- resolves domains to current IP addresses
- performs reverse DNS for IP addresses when available
- adds analyst-focused notes and limitations

### Validation Results

`github.com`

- resolved successfully to a public IP
- classified as public
- DNS result documented as point-in-time context

`198.51.100.25`

- classified as documentation/test space
- correctly identified as synthetic lab data
- no reverse-DNS hostname returned

`192.168.4.20`

- classified as RFC1918 private space
- reverse-resolved to `Ed_T14`
- provided useful internal-asset context

## Integrated Workflow

The authentication analyzer was upgraded to reuse the IOC enrichment utility with:

```text
--enrich-sources
```

This allows one command to perform:

```text
raw SSH logs
    -> field extraction
    -> event summary
    -> time-window correlation
    -> source-IP enrichment
    -> investigation indicators
```

Both authentication datasets were successfully validated with integrated enrichment.

## Evidence

Validation evidence is stored in:

- `docs/evidence/auth-log-automation-results.md`
- `docs/evidence/ioc-enrichment-results.md`

## Acceptance Criteria Review

- Script processes sample data successfully: **Complete**
- Output supports an investigation use case: **Complete**
- Useful fields extracted: **Complete**
- Failed/successful authentication summary: **Complete**
- IOC/indicator enrichment added: **Complete**
- Readable investigation output generated: **Complete**
- Inputs, outputs, assumptions, and limitations documented: **Complete**
- Code and example results committed: **Complete**

## Lessons Learned

1. Automation is most useful when it reduces repetitive analyst work without replacing analyst judgment.
2. Event ordering matters when correlating authentication behavior.
3. Time-window logic makes detections more precise than simple event counting.
4. Enrichment should add context rather than automatically label indicators as malicious.
5. Private and synthetic IP ranges should be handled differently from real public indicators.
6. Reusable modules make it easier to combine parsing, correlation, and enrichment into a single workflow.

## Next Phase

Phase 6 will focus on portfolio polish:

- presentation quality
- diagrams
- evidence organization
- refined write-ups
- resume-ready project language
- GitHub profile visibility
