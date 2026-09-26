# Phase 7 Windows OpenSSH Multi-User Validation

## Test
- Date: 2026-09-26, approximately 17:57 CDT
- Windows host and Wazuh agent: Ed_T14 (agent 001)
- Source: Mac mini, Tailscale IP 100.127.218.101
- Data source: OpenSSH/Operational, Event ID 4
- Controlled activity: SSH connections using invalid usernames fakeuser, admin, and support within five minutes

## Observed result
- Windows Event Viewer recorded `Invalid user <username> from 100.127.218.101 port <port>`.
- The Wazuh manager received the OpenSSH events through the Windows agent.
- Custom rule 100100, level 5, generated an alert for each invalid-user event.
- Threat Hunting displayed three rule 100100 alerts.
- The five-minute PPL query returned 3 attempts, 3 distinct usernames, and source IP 100.127.218.101.
- The query extracts username and source IP from `data.win.eventdata.payload` at search time.

## Reproduction
- Rule: `configs/wazuh/openssh-invalid-user-rules.xml`
- Query: `queries/openssh-spray-5m.ppl`
- Screenshot: `docs/evidence/phase-7-openssh-spray-query.png`

## Analyst interpretation
One source attempted three invalid usernames against the same Windows SSH server within five minutes. This is consistent with username enumeration or an early spray-like pattern. The activity was authorized lab validation; disposition: test, no incident escalation.

## Limits and follow-up
- The controlled SSH commands used BatchMode and did not submit passwords. This test does not prove password guessing occurred.
- Rule 100100 alerts on individual invalid usernames. The three-distinct-user condition currently returns a query result; it does not generate its own alert.
- Negative cases remain untested: repeated attempts against one username, attempts from different source IPs, and attempts spread beyond five minutes.
- Build a correlated alert for the distinct-user condition, test all negative cases, and document false-positive tuning before marking the planned spray detection complete.
