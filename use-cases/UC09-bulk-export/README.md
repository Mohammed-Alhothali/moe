[All use cases](../../README.md#the-use-cases) · Previous: [UC08](../UC08-price-override-abuse/README.md) · Next: [UC10](../UC10-phishing-attachment/README.md)

# UC09: Bulk export of pilgrim data

| | |
|---|---|
| **Tactic** | Collection / Exfiltration |
| **ATT&CK** | [T1213](https://attack.mitre.org/techniques/T1213/) Data from Information Repositories |
| **Runs on** | Laptop browser (portal) |
| **Top rule** | 110904 (level 14) |
| **Rules** | [`wazuh/rules/pp-090-uc09_bulk_export_rules.xml`](../../wazuh/rules/pp-090-uc09_bulk_export_rules.xml) |
| **Regression cases** | [`tests/cases/uc09.json`](../../tests/cases/uc09.json) |

## Why it matters

An exported manifest of names, passports and phones is exactly what fake-Hajj-package scammers buy. Normal exports are an agency's own few hundred pilgrims; thousands at once must be explained.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)
- CDB list: [`wazuh/lists/pp-approved-exporters`](../../wazuh/lists/pp-approved-exporters)

## Detection logic

- 110901: an export of 1,000 records or more (regex `^[1-9]\d{3,}$` on `record_count`).
- 110902 (13): ...by an account not on `pp-approved-exporters`.
- 110903 (12): ...outside working hours (`<time>10 pm - 6 am</time>`).
- 110904 (14): non-approved and off-hours.

### Rules (4 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110901 | 10 | UC09 Bulk export: `$(username)` [`$(role)`] exported `$(record_count)` pilgrim records (scope: `$(scope)`). | T1213 |
| 110902 | 13 | UC09 Bulk export by a non-approved account: `$(username)` [`$(role)`] exported `$(record_count)` pilgrim records. | T1213 |
| 110903 | 12 | UC09 Off-hours bulk export: `$(username)` exported `$(record_count)` pilgrim records outside working hours. | T1213 |
| 110904 | 14 | UC09 Off-hours bulk export by a non-approved account: `$(username)` exported `$(record_count)` pilgrim records. | T1213 |

Built on the shared portal base rule 110018 in [`wazuh/rules/pp-000-portal_base_rules.xml`](../../wazuh/rules/pp-000-portal_base_rules.xml).

<details>
<summary>Rule XML</summary>

```xml
<rule id="110901" level="10">
  <if_sid>110018</if_sid>
  <field name="record_count" type="pcre2">^[1-9]\d{3,}$</field>
  <description>UC09 Bulk export: $(username) [$(role)] exported $(record_count) pilgrim records (scope: $(scope)).</description>
  <mitre>
    <id>T1213</id>
  </mitre>
  <group>pp_bulk_export,</group>
</rule>

<rule id="110902" level="13">
  <if_sid>110901</if_sid>
  <list field="username" lookup="not_match_key">etc/lists/pp-approved-exporters</list>
  <description>UC09 Bulk export by a non-approved account: $(username) [$(role)] exported $(record_count) pilgrim records.</description>
  <mitre>
    <id>T1213</id>
  </mitre>
  <group>pp_bulk_export,</group>
</rule>

<rule id="110903" level="12">
  <if_sid>110901</if_sid>
  <time>10 pm - 6 am</time>
  <description>UC09 Off-hours bulk export: $(username) exported $(record_count) pilgrim records outside working hours.</description>
  <mitre>
    <id>T1213</id>
  </mitre>
  <group>pp_bulk_export,</group>
</rule>

<rule id="110904" level="14">
  <if_sid>110902</if_sid>
  <time>10 pm - 6 am</time>
  <description>UC09 Off-hours bulk export by a non-approved account: $(username) exported $(record_count) pilgrim records.</description>
  <mitre>
    <id>T1213</id>
  </mitre>
  <group>pp_bulk_export,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110902, level 13:** UC09 Bulk export by a non-approved account: agency.in01 [agency] exported 1200 pilgrim records.

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"data_export","srcip":"192.168.20.45","username":"agency.in01","role":"agency","record_count":"1200","scope":"own","export_format":"csv"}
```

**110901, level 10:** UC09 Bulk export: staff.reporting [staff] exported 1500 pilgrim records (scope: all).

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"data_export","srcip":"192.168.20.45","username":"staff.reporting","role":"staff","record_count":"1500","scope":"all","export_format":"csv"}
```

## How to test it live

Runs on: Laptop browser (portal).

1. Sign in as `agency.in01` / `Agency#2026` (the largest agency, 1,200 pilgrims), open **Export** and **Download CSV**. This gives 110902, or 110904 at night.
2. As `staff.reporting` / `Staff#2026` the same export gives 110901 (approved account).

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- The approved-exporters list is owned by the Data Protection Officer.
- Working hours follow the manager's clock; widen the window for 24/7 operations shifts during the season.

## Regression cases

5 cases (4 positive, 1 negative) in [`tests/cases/uc09.json`](../../tests/cases/uc09.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC09-01 | positive | Approved reporting account exports 1,500 records in working hours -> 110901 |
| UC09-02 | positive | Largest agency exports its own 1,200 pilgrims -> 110902 (not an approved exporter) |
| UC09-03 | positive | Approved account exports at 23:00 -> 110903 |
| UC09-04 | positive | Non-approved account exports at 02:00 -> 110904 (level 14) |
| UC09-05 | negative | Agency exports its own 300 pilgrims (no alert) |

## How to improve it

- Add a daily cumulative-volume check (many small exports that add up).
- Correlate with UC03 (takeover) or UC05 (harvesting) for a level-15 data-theft chain.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
