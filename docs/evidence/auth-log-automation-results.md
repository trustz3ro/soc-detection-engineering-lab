# Authentication Automation — Example Results

## Test 1 — Failed Logins Followed by Success

Command:

```powershell
python .\scripts\analyze_auth_logs.py .\data\sample-logs\auth.log
```

Observed summary:

```text
Parsed events: 4
Failed authentications: 3
Successful authentications: 1

Source IPs:
  - 192.0.2.10 (documentation/test range)

Indicators:
  - Failed-then-success pattern: 192.0.2.10 had 3 failed attempt(s) and 1 successful login(s).
```

The report also produced a chronological timeline showing three failed SSH password attempts against `admin`, followed by one successful login for `edwardjohnson`.

## Test 2 — Password Spray

Command:

```powershell
python .\scripts\analyze_auth_logs.py .\data\sample-logs\password_spray.log
```

Observed summary:

```text
Parsed events: 5
Failed authentications: 5
Successful authentications: 0

Source IPs:
  - 198.51.100.25 (documentation/test range)

Indicators:
  - Possible password spray: 198.51.100.25 targeted 5 unique usernames (admin, edwardjohnson, guest, root, support).
```

The event timeline showed five failed SSH authentication attempts from the same source IP against five different usernames.

## Validation Outcome

The automation utility successfully:

- parsed both sample datasets
- extracted host, username, source IP, source port, result, and event type
- summarized failed and successful activity
- classified the synthetic source IPs as documentation/test ranges
- generated a readable event timeline
- identified the failed-then-success pattern
- identified the password-spray pattern

## Analyst Note

The script correctly treats these findings as investigation indicators rather than proof of malicious activity.

This preserves the analyst's role in validating context, intent, timing, and surrounding telemetry.

## Current Limitation

The failed-then-success indicator currently checks whether the same source IP has both failed and successful events in the input dataset.

A future improvement should explicitly verify that the successful event occurred **after** the failures within a defined time window.


## Time-Window Correlation Validation

The authentication analyzer was retested after adding ordered time-window correlation.

### Test 1 — Failed Logins Followed by Success

Observed result:

```text
Parsed events: 4
Failed authentications: 3
Successful authentications: 1
Failed-then-success window: 10 minute(s)

Indicators:
  - Failed-then-success pattern: 192.0.2.10 had 3 failed attempt(s) before a successful login within 10 minute(s) (elapsed 13 seconds).
```

This confirms that the detector now verifies:
- failures occurred before the success
- the success occurred within the configured 10-minute window
- elapsed time is calculated and reported

### Test 2 — Password Spray

Observed result:

```text
Parsed events: 5
Failed authentications: 5
Successful authentications: 0
Failed-then-success window: 10 minute(s)

Indicators:
  - Possible password spray: 198.51.100.25 targeted 5 unique usernames (admin, edwardjohnson, guest, root, support).
```

The password-spray detection continued to work correctly and did not generate a failed-then-success indicator because no successful authentication was present.

## Validation Outcome

The upgraded analyzer passed both tests.

Current validated capabilities now include:
- SSH authentication parsing
- source IP classification
- password-spray detection
- ordered failed-then-success correlation
- configurable correlation window
- elapsed-time reporting
- readable investigation timeline


## Integrated Authentication + IOC Enrichment Validation

The authentication analyzer was validated with source-IP enrichment enabled:

```powershell
python .\scripts\analyze_auth_logs.py .\data\sample-logs\auth.log --enrich-sources
```

Observed result:

```text
Parsed events: 4
Failed authentications: 3
Successful authentications: 1
Failed-then-success window: 10 minute(s)

Source IP enrichment:
  - 192.0.2.10
      Classification: documentation/test range
      Reverse DNS: None
      Note: No reverse-DNS hostname was returned.
      Note: This address belongs to an RFC documentation range and should not be treated as a real external IOC.

Indicators:
  - Failed-then-success pattern: 192.0.2.10 had 3 failed attempt(s) before a successful login within 10 minute(s) (elapsed 13 seconds).
```

This confirms the combined workflow can perform authentication parsing, ordered time-window correlation, and IOC enrichment in a single analyst run.

The source IP was correctly identified as synthetic lab data, while the failed-then-success sequence remained intact.
