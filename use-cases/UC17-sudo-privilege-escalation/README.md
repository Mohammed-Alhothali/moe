[All use cases](../../README.md#the-use-cases) · Previous: [UC16](../UC16-expired-seasonal-accounts/README.md) · Next: [UC18](../UC18-cron-persistence/README.md)

# UC17: Privilege escalation on the web server through sudo

| | |
|---|---|
| **Tactic** | Privilege Escalation |
| **ATT&CK** | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Web Shell, [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Sudo and Sudo Caching |
| **Runs on** | web01 terminal |
| **Top rule** | 111705 (level 15) |
| **Rules** | [`wazuh/rules/pp-170-uc17_sudo_privilege_rules.xml`](../../wazuh/rules/pp-170-uc17_sudo_privilege_rules.xml) |
| **Regression cases** | [`tests/cases/uc17.json`](../../tests/cases/uc17.json) |

## Why it matters

web01 serves the booking portal. An attacker who gets a web shell runs as `www-data`; the next step is root, either by planting a sudoers rule or by abusing sudo. Root on web01 means the whole pilgrim database and the ability to tamper with bookings.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| File integrity monitoring (web01) | syscheck realtime + `report_changes` on `/etc/sudoers`, `/etc/sudoers.d` | Built-in syscheck |
| sudo messages | `/var/log/auth.log` on web01 (shared `agent.conf`) | Built-in `sudo` |

- CDB list: [`wazuh/lists/pp-service-accounts`](../../wazuh/lists/pp-service-accounts)

## Detection logic

- 111701 (10): `/etc/sudoers` or a drop-in under `/etc/sudoers.d` was modified or deleted. 111702 (12): a new drop-in appeared.
- 111703 (13): the change ADDS a rule with `NOPASSWD`, `!authenticate` or full `ALL=(ALL) ALL`. The rule reads the line diff that `report_changes` attaches to the FIM event and ignores comment lines.
- 111704 (12): a web service account (`etc/lists/pp-service-accounts`) ran sudo. The list lookup on `user` checks the caller (srcuser), not the target.
- 111705 (15) / 111706 (14): the sudo attempt came within 30 minutes of a script being planted in the web root (UC07 110701) or of the web account running unexpected programs (UC07 110702).
- Wazuh will not reuse an event that already triggered a correlation of the same or higher level, so these chains key on 110701/110702 rather than on UC07's level-15 110703.

### Rules (6 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111701 | 10 | UC17 sudo configuration changed on the web server: `$(file)` | T1548.003 |
| 111702 | 12 | UC17 New sudoers drop-in file on the web server: `$(file)` | T1548.003 |
| 111703 | 13 | UC17 sudoers change grants passwordless or full root rights: `$(file)` | T1548.003 |
| 111704 | 12 | UC17 Web service account `$(srcuser)` tried to run sudo as `$(dstuser)`: `$(command)` | T1548.003 |
| 111705 | 15 | UC17 Web shell to root attempt: `$(srcuser)` ran sudo within 30 minutes of a script being planted in the web root | T1548.003, T1505.003 |
| 111706 | 14 | UC17 Web account escalation attempt: `$(srcuser)` ran sudo within 30 minutes of running unexpected programs on the web server (UC07) | T1548.003, T1505.003 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111701" level="10">
  <if_sid>550, 553</if_sid>
  <field name="file" type="pcre2">^/etc/sudoers(\.d/.+)?$</field>
  <description>UC17 sudo configuration changed on the web server: $(file)</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
  <group>pp_privesc,pp_sudoers_change,</group>
</rule>

<rule id="111702" level="12">
  <if_sid>554</if_sid>
  <field name="file" type="pcre2">^/etc/sudoers\.d/.+</field>
  <description>UC17 New sudoers drop-in file on the web server: $(file)</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
  <group>pp_privesc,</group>
</rule>

<rule id="111703" level="13">
  <if_group>pp_sudoers_change</if_group>
  <field name="changed_content" type="pcre2">(?m)^>\s*[^#\s].*(\bNOPASSWD\b|!authenticate|=\s*\(\s*ALL\s*(:\s*ALL\s*)?\)\s*ALL\s*$)</field>
  <description>UC17 sudoers change grants passwordless or full root rights: $(file)</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
  <group>pp_privesc,</group>
</rule>

<rule id="111704" level="12">
  <if_sid>5400</if_sid>
  <list field="user" lookup="match_key">etc/lists/pp-service-accounts</list>
  <description>UC17 Web service account $(srcuser) tried to run sudo as $(dstuser): $(command)</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
  <group>pp_privesc,</group>
</rule>

<rule id="111705" level="15" timeframe="1800">
  <if_sid>111704</if_sid>
  <if_matched_sid>110701</if_matched_sid>
  <description>UC17 Web shell to root attempt: $(srcuser) ran sudo within 30 minutes of a script being planted in the web root</description>
  <mitre>
    <id>T1548.003</id>
    <id>T1505.003</id>
  </mitre>
  <group>pp_privesc,</group>
</rule>

<rule id="111706" level="14" timeframe="1800">
  <if_sid>111704</if_sid>
  <if_matched_group>pp_webshell</if_matched_group>
  <description>UC17 Web account escalation attempt: $(srcuser) ran sudo within 30 minutes of running unexpected programs on the web server (UC07)</description>
  <mitre>
    <id>T1548.003</id>
    <id>T1505.003</id>
  </mitre>
  <group>pp_privesc,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111702, level 12:** UC17 New sudoers drop-in file on the web server: /etc/sudoers.d/pp-uc17-test

```
File '/etc/sudoers.d/pp-uc17-test' added
```

**111701, level 10:** UC17 sudo configuration changed on the web server: /etc/sudoers

```
File '/etc/sudoers' modified
```

## How to test it live

Runs on: web01 terminal.

1. web01: `printf 'Defaults:portal !lecture\n' > /tmp/pp-uc17 && sudo visudo -cf /tmp/pp-uc17 && sudo install -m 0440 /tmp/pp-uc17 /etc/sudoers.d/pp-uc17-test` gives 111702 (new drop-in; visudo checks the syntax first).
2. web01: `echo 'nobody ALL=(ALL) NOPASSWD: /usr/bin/true' | sudo tee -a /etc/sudoers.d/pp-uc17-test && sudo visudo -c` gives 111703 (`nobody` cannot log in and `true` does nothing).
3. web01: `sudo -u www-data sudo -n true` gives 111704 (www-data is refused).
4. Clean up: `sudo rm /etc/sudoers.d/pp-uc17-test`.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Only ADDED, non-comment lines are read: removing rights or adding a comment stays at 111701 (case UC17-05).
- Administrators using sudo keep Wazuh's normal levels (case UC17-09).

## Regression cases

10 cases (8 positive, 2 negative) in [`tests/cases/uc17.json`](../../tests/cases/uc17.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC17-01 | positive | /etc/sudoers edited (comment only) -> 111701 |
| UC17-02 | positive | New drop-in file in /etc/sudoers.d -> 111702 |
| UC17-03 | positive | Drop-in edited to add a NOPASSWD rule -> 111703 |
| UC17-04 | positive | Full ALL=(ALL:ALL) ALL granted in /etc/sudoers -> 111703 |
| UC17-05 | negative | NOPASSWD only inside a comment stays at 111701 (FP control) |
| UC17-06 | positive | Web service account runs sudo (classic syslog time) -> 111704 |
| UC17-07 | positive | Web service account runs sudo (Ubuntu 24.04 ISO time) -> 111704 |
| UC17-08 | positive | Script planted in the web root, run, then sudo by www-data -> 111705 |
| UC17-09 | negative | Administrator uses sudo normally (no UC17 alert) |
| UC17-10 | positive | Web account runs an unexpected program, then sudo -> 111706 |

## How to improve it

- Turn on FIM `whodata` for these paths to show which process and login user made the change.
- Active response: lock the service account's shell when 111705 fires.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
