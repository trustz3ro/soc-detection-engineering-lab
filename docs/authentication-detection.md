# Authentication Detection: Repeated Failures Followed by Success

## Objective

Detect a suspicious authentication pattern in which multiple failed SSH login attempts from the same source are followed by a successful login.

## Test Data

The lab uses a small synthetic SSH authentication log stored at:

`data/sample-logs/auth.log`

The sample contains three failed login attempts followed by one successful login from the same source IP.

## Detection Logic

The Python script:

`scripts/detect_auth_pattern.py`

performs the following steps:

1. Reads the authentication log line by line.
2. Counts entries containing `Failed password`.
3. Extracts the source IPv4 address from failed authentication events.
4. Detects an `Accepted password` event after at least three failures.
5. Extracts the username from the successful login event.
6. Prints an alert with the failed-attempt count, source IP, and username.

## Example Result

```text
Failed login attempts: 3
ALERT: Successful login detected after multiple failed attempts.
Source IP: 192.0.2.10
Username: edwardjohnson
```

## Security Relevance

Repeated authentication failures followed by a successful login can indicate password guessing, credential stuffing, or a user repeatedly entering an incorrect password. The pattern alone is not proof of malicious activity, so an analyst should correlate it with the source IP, affected account, timing, device context, and other telemetry before escalating.

## Detection Engineering Notes

This first version is intentionally simple and demonstrates the core detection workflow. Future improvements will include:

- grouping failures by source IP and username
- using a defined time window
- configurable thresholds
- parsing real system logs
- reducing false positives
- producing structured JSON output
- integrating the detection into a SIEM or alerting pipeline

## Lab Status

Working prototype completed and tested successfully in the Ubuntu homelab environment.
