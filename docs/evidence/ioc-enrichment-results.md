# IOC Enrichment — Validation Results

## Test 1 — Public Domain

Command:

```powershell
python .\scripts\enrich_ioc.py github.com
```

Observed result:

```text
Indicator: github.com
Type: domain
Classification: public
Resolved / observed IPs:
  - 140.82.113.3 (public)
Reverse DNS: None
```

The utility correctly resolved the domain to a public IP address and noted that DNS results are point-in-time observations that may change.

## Test 2 — Documentation / Test IP

Command:

```powershell
python .\scripts\enrich_ioc.py 198.51.100.25
```

Observed result:

```text
Indicator: 198.51.100.25
Type: IPv4
Classification: documentation/test range
Reverse DNS: None
```

The utility correctly identified the address as belonging to an RFC documentation range and warned that it should not be treated as a real external IOC.

## Test 3 — Private Lab IP

Command:

```powershell
python .\scripts\enrich_ioc.py 192.168.4.20
```

Observed result:

```text
Indicator: 192.168.4.20
Type: IPv4
Classification: private RFC1918
Reverse DNS: Ed_T14
```

The utility correctly identified the address as private RFC1918 space and successfully returned the reverse-DNS hostname `Ed_T14`.

## Validation Outcome

The IOC enrichment utility successfully demonstrated:

- domain resolution
- public IP classification
- RFC documentation/test-range identification
- RFC1918 private-address classification
- reverse-DNS lookup
- analyst-focused context and limitations

## Analyst Interpretation

The tool adds useful context without assigning a malicious/benign verdict.

This is important in SOC work because enrichment should support investigation decisions rather than replace analyst judgment.

For example:

- `github.com` resolving to a public IP is expected but not proof of safety
- `198.51.100.25` is synthetic lab data, not a real external threat source
- `192.168.4.20` maps back to `Ed_T14`, which provides useful internal asset context during investigation
