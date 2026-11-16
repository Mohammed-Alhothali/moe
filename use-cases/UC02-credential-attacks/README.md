[All use cases](../../README.md#the-use-cases) · Previous: [UC01](../UC01-booking-bot/README.md) · Next: [UC03](../UC03-account-takeover/README.md)

# UC02: Credential stuffing and password guessing

| | |
|---|---|
| **Tactic** | Credential Access |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing, [T1110.004](https://attack.mitre.org/techniques/T1110/004/) Credential Stuffing |
| **Runs on** | Laptop browser (portal) |
| **Top rule** | 110202 (level 11) |
| **Rules** | [`wazuh/rules/pp-020-uc02_credential_attacks_rules.xml`](../../wazuh/rules/pp-020-uc02_credential_attacks_rules.xml) |
| **Regression cases** | [`tests/cases/uc02.json`](../../tests/cases/uc02.json) |

## Why it matters

Leaked email/password lists are replayed against every big portal. A hijacked pilgrim account exposes a passport and payments; a hijacked agency account exposes thousands of pilgrims and their bookings.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)
- CDB list: [`wazuh/lists/pp-trusted-ips`](../../wazuh/lists/pp-trusted-ips)

## Detection logic

- The base rules split failures by reason: 110011 is a wrong password for a real account (`pp_bad_password`), 110012 is a non-existent account (`pp_unknown_user`).
- 110201 (level 8): 8 failures from one IP for 8 different accounts in 2 min.
- 110202 (level 11): 5 attempts for non-existent accounts from one IP in 2 min. Combo lists are full of accounts the portal never had; real users almost never mistype a username into a non-existent account.
- 110203 (level 10): 6 wrong passwords for one account in 2 min, from any IP (password guessing).
- All three carry group `pp_bruteforce`, which UC03 correlates with a later success.

### Rules (3 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110201 | 8 | UC02 Possible credential stuffing: failed logins for 8+ different accounts from `$(srcip)` in 2 minutes. | T1110.004 |
| 110202 | 11 | UC02 Credential stuffing: `$(srcip)` tried 5+ non-existent accounts in 2 minutes (leaked combo list pattern). | T1110.004 |
| 110203 | 10 | UC02 Password guessing: 6+ wrong passwords for account `$(username)` in 2 minutes (latest from `$(srcip)`). | T1110.001 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="110201" level="8" frequency="8" timeframe="120">
  <if_matched_group>pp_login_failed</if_matched_group>
  <same_srcip />
  <different_field>username</different_field>
  <list field="srcip" lookup="not_address_match_key">etc/lists/pp-trusted-ips</list>
  <description>UC02 Possible credential stuffing: failed logins for 8+ different accounts from $(srcip) in 2 minutes.</description>
  <mitre>
    <id>T1110.004</id>
  </mitre>
  <group>pp_bruteforce,</group>
</rule>

<rule id="110202" level="11" frequency="5" timeframe="120">
  <if_matched_group>pp_unknown_user</if_matched_group>
  <same_srcip />
  <different_field>username</different_field>
  <list field="srcip" lookup="not_address_match_key">etc/lists/pp-trusted-ips</list>
  <description>UC02 Credential stuffing: $(srcip) tried 5+ non-existent accounts in 2 minutes (leaked combo list pattern).</description>
  <mitre>
    <id>T1110.004</id>
  </mitre>
  <group>pp_bruteforce,</group>
</rule>

<rule id="110203" level="10" frequency="6" timeframe="120">
  <if_matched_group>pp_bad_password</if_matched_group>
  <same_field>username</same_field>
  <description>UC02 Password guessing: 6+ wrong passwords for account $(username) in 2 minutes (latest from $(srcip)).</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>pp_bruteforce,pp_password_guessing,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110202, level 11:** UC02 Credential stuffing: 203.0.113.31 tried 5+ non-existent accounts in 2 minutes (leaked combo list pattern).

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"login_failed","srcip":"203.0.113.31","username":"user4@mail.example","role":"anonymous","country":"NG","reason":"unknown_user"}
```

**110203, level 10:** UC02 Password guessing: 6+ wrong passwords for account agency.in01 in 2 minutes (latest from 203.0.113.41).

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"login_failed","srcip":"203.0.113.41","username":"agency.in01","role":"anonymous","country":"IN","reason":"bad_password"}
```

## How to test it live

Runs on: Laptop browser (portal).

1. Sign out. On **Sign in**, enter 5 made-up usernames with any password, which gives 110202.
2. Enter wrong passwords for `pilgrim0001` to `pilgrim0008`, which gives 110201.
3. Enter a wrong password for `agency.in01` 6 times, which gives 110203.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Hotel and carrier NAT: several genuine pilgrims mistyping passwords from one IP is normal, so 110201 stays at medium and the high-confidence signal is 110202.
- The internal vulnerability scanner and load-test agents are allowlisted in `pp-trusted-ips`.
- Thresholds sit just above normal behaviour (a person retries 2-3 times) and are documented here for tuning.
- Duplicate suppression: nginx logs each failed sign-in as HTTP 401, which would also raise Wazuh's generic 'Web server 400 error code' (31101). Tuning rule 110021 absorbs exactly those lines with `no_log`, so the dashboard shows the UC02 alert only (regression cases UC02-06 and UC02-07).

## Regression cases

7 cases (4 positive, 3 negative) in [`tests/cases/uc02.json`](../../tests/cases/uc02.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC02-01 | positive | Wrong passwords for 8 different accounts from one IP -> 110201 |
| UC02-02 | positive | 5 non-existent accounts from one IP -> 110202 (high confidence) |
| UC02-03 | positive | 6 wrong passwords for one agency account -> 110203 |
| UC02-04 | negative | Hotel NAT: 7 pilgrims mistype passwords from one IP (no alert) |
| UC02-05 | negative | Internal scanner on the trusted list is ignored |
| UC02-06 | negative | Tuning: nginx 401 for a failed sign-in is absorbed (no duplicate 31101 alert) |
| UC02-07 | positive | Tuning keeps other 4xx: a scanner probing /wp-admin still raises 31101 |

## How to improve it

- Active response on 110202 to block the IP for 15 minutes.
- Enrich `srcip` with a threat-intelligence CDB list of known proxy and botnet ranges.
- Track the ratio of failures to successes per IP over an hour (SIEM dashboard).

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
