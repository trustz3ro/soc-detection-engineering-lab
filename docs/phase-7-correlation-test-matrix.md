# Phase 7 OpenSSH correlation test matrix

Detection target: one source IP attempts at least three distinct invalid
usernames against ED_T14 within five minutes.

| Case | Input pattern | Expected correlated alert | Status |
|---|---|---|---|
| Positive | Three distinct usernames, one source IP, within five minutes | Yes | Query observed September 26; alert pending |
| Repeated username | Three events for one username from one IP | No | Pending |
| Multiple sources | Three usernames spread across different source IPs | No | Pending |
| Outside window | Three usernames from one IP over more than five minutes | No | Pending |

Rule 100100 currently alerts on each invalid-user event. The existing PPL
query returned three distinct usernames from 100.127.218.101 on September 26.
A correlated alert and the negative cases have not yet been validated.

For each test, record event times, source IPs, usernames, individual alerts,
correlated alert result, query result, and a screenshot. Controlled attempts
used invalid usernames without submitting passwords; do not describe this
evidence as password guessing.
