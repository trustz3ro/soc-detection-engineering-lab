# OpenSSH correlation automation

## Behavior

A systemd timer runs the correlator approximately every 15 seconds after
the previous run finishes. It detects three distinct invalid usernames
against Ed_T14 from one source IP within 300 seconds.

JSON results are appended to /var/log/openssh-correlation.json.
Wazuh collects the file and generates level-10 rule 100110.

State is stored in /var/lib/openssh-correlation/state.json.
Previously observed events remain cached for five minutes across runs.
One alert is emitted per target/source episode. A group becomes eligible
again after a run observes it below the three-username threshold.

## Validation

Validated October 15, 2026, America/Chicago; evidence uses October 16 UTC.

- All 17 tests passed on the Mac mini and Wazuh Python 3.10.
- The timer generated one live alert for auto_alpha, auto_beta, auto_gamma.
- Four subsequent runs emitted zero duplicate alerts.
- Cached-event rollover handling passed automated testing.
- Actual live log rollover has not been observed.

Evidence:

- [Automated alert](evidence/phase-7-automated-alert.json)
- [Timer journal](evidence/phase-7-automation-journal.txt)

## Installation

Prerequisites: working rule 100100, JSON collection of
/var/log/openssh-correlation.json, rule 100110, and a healthy Wazuh manager.

From the repository on the Wazuh server, install both Python scripts in
/opt/openssh-correlation with root ownership and mode 640.
Install the service and timer from configs/systemd into
/etc/systemd/system with root ownership and mode 644.

Validate the unit files with systemd-analyze verify, then run:

    sudo systemctl daemon-reload
    sudo systemctl start openssh-correlation.service
    sudo systemctl status openssh-correlation.service --no-pager -l

Confirm the oneshot run succeeded before enabling scheduling:

    sudo systemctl enable --now openssh-correlation.timer

The service uses Wazuh's bundled Python interpreter.
Its StateDirectory setting creates the persistent state directory.

## Operations

    sudo systemctl list-timers --all openssh-correlation.timer
    sudo journalctl -u openssh-correlation.service -n 20 --no-pager
    sudo systemctl is-active wazuh-manager

A successful oneshot service normally returns to inactive.
The timer should remain active.

## Rollback

    sudo systemctl disable --now openssh-correlation.timer
    sudo systemctl stop openssh-correlation.service

This stops automation while retaining scripts, state, evidence, and
Wazuh rules. The original manual correlator remains available.

## Limitations

- Cache preserves only events already read; unread rotated events can be missed.
- The current input file is scanned in full each run; intended for this lab.
- A crash between output append and state save can cause a duplicate.
- Corrupt state fails the run and requires investigation.
- Multiple writers must not share the state/output files.
- Automatic manager recovery and service-failure notifications are not configured.
- A failed manager can prevent event processing while the timer continues.
- Root execution and write access to /var/log exceed ideal production permissions.
