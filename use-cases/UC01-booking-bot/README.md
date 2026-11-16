[All use cases](../../README.md#the-use-cases) · Next: [UC02](../UC02-credential-attacks/README.md)

# UC01: Automated booking abuse (slot scalping bots)

| | |
|---|---|
| **Tactic** | Impact |
| **ATT&CK** | [T1499.003](https://attack.mitre.org/techniques/T1499/003/) Application Exhaustion Flood |
| **Runs on** | Laptop browser (portal) |
| **Top rule** | 110102 (level 12) |
| **Rules** | [`wazuh/rules/pp-010-uc01_booking_bot_rules.xml`](../../wazuh/rules/pp-010-uc01_booking_bot_rules.xml) |
| **Regression cases** | [`tests/cases/uc01.json`](../../tests/cases/uc01.json) |

## Why it matters

Hajj and Umrah arrival slots are scarce and sell out in minutes. Bots grab them for resale on the black market, so genuine pilgrims lose their place and fake 'guaranteed package' sellers get stock. No input validation stops this: each request is a perfectly valid booking. Only behaviour gives it away.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)
- CDB list: [`wazuh/lists/pp-trusted-ips`](../../wazuh/lists/pp-trusted-ips)

## Detection logic

- Base rule 110013 (level 2) tags every `booking_attempt`. It is not shown as an alert but is counted.
- 110101: the same `username` makes 10 attempts within 60 s (`frequency=10`, `same_field username`). A person manages 1-3 a minute through the UI.
- 110102: 15 attempts from one `srcip` within 60 s, using rotating accounts (`same_srcip`, `different_field username`). This is a bot farm spreading load across stolen or fake accounts.

### Rules (2 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110101 | 10 | UC01 Booking bot: account `$(username)` made 10+ booking attempts in 60 seconds from `$(srcip)`. | T1499.003 |
| 110102 | 12 | UC01 Booking bot farm: 15+ booking attempts in 60 seconds from `$(srcip)` using rotating accounts. | T1499.003 |

Built on the shared portal base rule 110013 in [`wazuh/rules/pp-000-portal_base_rules.xml`](../../wazuh/rules/pp-000-portal_base_rules.xml).

<details>
<summary>Rule XML</summary>

```xml
<rule id="110101" level="10" frequency="10" timeframe="60" ignore="120">
  <if_matched_sid>110013</if_matched_sid>
  <same_field>username</same_field>
  <list field="srcip" lookup="not_address_match_key">etc/lists/pp-trusted-ips</list>
  <description>UC01 Booking bot: account $(username) made 10+ booking attempts in 60 seconds from $(srcip).</description>
  <mitre>
    <id>T1499.003</id>
  </mitre>
  <group>pp_bot,</group>
</rule>

<rule id="110102" level="12" frequency="15" timeframe="60" ignore="120">
  <if_matched_sid>110013</if_matched_sid>
  <same_srcip />
  <different_field>username</different_field>
  <list field="srcip" lookup="not_address_match_key">etc/lists/pp-trusted-ips</list>
  <description>UC01 Booking bot farm: 15+ booking attempts in 60 seconds from $(srcip) using rotating accounts.</description>
  <mitre>
    <id>T1499.003</id>
  </mitre>
  <group>pp_bot,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110102, level 12:** UC01 Booking bot farm: 15+ booking attempts in 60 seconds from 203.0.113.21 using rotating accounts.

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"booking_attempt","srcip":"203.0.113.21","username":"pilgrim0014","role":"pilgrim","slot_id":"300","result":"booked"}
```

**110101, level 10:** UC01 Booking bot: account pilgrim0042 made 10+ booking attempts in 60 seconds from 203.0.113.20.

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"booking_attempt","srcip":"203.0.113.20","username":"pilgrim0042","role":"pilgrim","slot_id":"209","result":"full"}
```

## How to test it live

Runs on: Laptop browser (portal).

1. Sign in as `pilgrim0042` / `Pilgrim#2026` and open **Bookings**.
2. Click **Book** on 10 different slots within a minute (results like *full* or *duplicate* still count).
3. In Wazuh, filter `rule.id:110101`. The alert names the account and source IP.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Thousands of pilgrims share hotel and carrier NAT addresses during the season, so the per-IP rule needs a higher threshold than the per-account rule.
- Known shared or test IPs (campaign offices, load-test agents) go in `etc/lists/pp-trusted-ips` and are skipped.
- `ignore="120"`: once a bot is flagged, the rule stays quiet for 2 minutes instead of firing every 10 requests.

## Regression cases

4 cases (2 positive, 2 negative) in [`tests/cases/uc01.json`](../../tests/cases/uc01.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC01-01 | positive | One account fires 10 booking attempts in a minute -> 110101 |
| UC01-02 | positive | 15 attempts from one IP, rotating accounts -> 110102 |
| UC01-03 | negative | 9 attempts stays under the threshold (no alert) |
| UC01-04 | negative | Load-test agent on the trusted list is ignored |

## How to improve it

- Add active response (`firewall-drop` on `srcip`, 10 min) for 110102.
- Feed CAPTCHA or bot-score results into the audit log and correlate with them.
- Baseline per-season booking rates and adapt the thresholds for opening day.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
