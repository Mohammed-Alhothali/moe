[All use cases](../../README.md#the-use-cases) · Previous: [UC02](../UC02-credential-attacks/README.md) · Next: [UC04](../UC04-impossible-travel/README.md)

# UC03: Account takeover after a credential attack

| | |
|---|---|
| **Tactic** | Initial Access |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts, [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force, [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing |
| **Runs on** | Laptop browser (portal) |
| **Top rule** | 110301 (level 13) |
| **Rules** | [`wazuh/rules/pp-030-uc03_account_takeover_rules.xml`](../../wazuh/rules/pp-030-uc03_account_takeover_rules.xml) |
| **Regression cases** | [`tests/cases/uc03.json`](../../tests/cases/uc03.json) |

## Why it matters

A failed attack is noise; a failed attack followed by a success is a compromised account. That is the moment the SOC must act: reset the password, kill the session and review what was booked or exported.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)

## Detection logic

- 110301: a `login_success` from an IP that raised any `pp_bruteforce` alert in the last 10 min (`if_sid 110010` + `if_matched_group pp_bruteforce` + `same_srcip`).
- 110302: a `login_success` for an account that was the target of password guessing (group `pp_password_guessing`) in the last 10 min, even if the attacker switched IP (`same_field username`).
- Both are level 13 and also carry `pp_login_success`, so UC04 still counts these logins.

### Rules (2 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110301 | 13 | UC03 Account takeover suspected: `$(username)` logged in from `$(srcip)` right after a credential attack from the same IP. | T1110, T1078 |
| 110302 | 13 | UC03 Account takeover suspected: `$(username)` logged in (from `$(srcip)`) shortly after a password-guessing attack on that account. | T1110.001, T1078 |

Built on the shared portal base rule 110010 in [`wazuh/rules/pp-000-portal_base_rules.xml`](../../wazuh/rules/pp-000-portal_base_rules.xml).

<details>
<summary>Rule XML</summary>

```xml
<rule id="110301" level="13" timeframe="600">
  <if_sid>110010</if_sid>
  <if_matched_group>pp_bruteforce</if_matched_group>
  <same_srcip />
  <description>UC03 Account takeover suspected: $(username) logged in from $(srcip) right after a credential attack from the same IP.</description>
  <mitre>
    <id>T1110</id>
    <id>T1078</id>
  </mitre>
  <group>pp_account_takeover,pp_login_success,</group>
</rule>

<rule id="110302" level="13" timeframe="600">
  <if_sid>110010</if_sid>
  <if_matched_group>pp_password_guessing</if_matched_group>
  <same_field>username</same_field>
  <description>UC03 Account takeover suspected: $(username) logged in (from $(srcip)) shortly after a password-guessing attack on that account.</description>
  <mitre>
    <id>T1110.001</id>
    <id>T1078</id>
  </mitre>
  <group>pp_account_takeover,pp_login_success,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110301, level 13:** UC03 Account takeover suspected: pilgrim0007 logged in from 203.0.113.40 right after a credential attack from the same IP.

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"login_success","srcip":"203.0.113.40","username":"pilgrim0007","role":"pilgrim","country":"NG","session":"s-0007"}
```

**110302, level 13:** UC03 Account takeover suspected: agency.in01 logged in (from 198.18.0.7) shortly after a password-guessing attack on that account.

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"login_success","srcip":"198.18.0.7","username":"agency.in01","role":"agency","country":"IN","session":"s-in01"}
```

## How to test it live

Runs on: Laptop browser (portal).

1. From your laptop, trigger 110202 (5 made-up usernames, see UC02).
2. Then sign in correctly as `pilgrim0007` / `Pilgrim#2026` from the same laptop, which gives 110301.
3. Or: 6 wrong passwords for `agency.in01`, then the right one (`Agency#2026`), which gives 110302.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- The correlation needs both halves, the attack and a success tied by IP or account, within 10 minutes.
- A different user signing in from a different IP after an attack does not fire (regression case UC03-03).

## Regression cases

3 cases (2 positive, 1 negative) in [`tests/cases/uc03.json`](../../tests/cases/uc03.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC03-01 | positive | Stuffing from an IP, then a success from that IP -> 110301 |
| UC03-02 | positive | Password guessing on an account, attacker switches IP, then success -> 110302 |
| UC03-03 | negative | Unrelated user logs in from another IP after an attack (no takeover alert) |

## How to improve it

- Active response: disable the account or revoke sessions through the portal API.
- Add a third correlation: takeover followed by a bulk export or price override (UC09/UC08) to reach level 15.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
