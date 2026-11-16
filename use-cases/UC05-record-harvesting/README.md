[All use cases](../../README.md#the-use-cases) · Previous: [UC04](../UC04-impossible-travel/README.md) · Next: [UC06](../UC06-sql-injection/README.md)

# UC05: Pilgrim record harvesting and authorization probing

| | |
|---|---|
| **Tactic** | Collection |
| **ATT&CK** | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application, [T1213](https://attack.mitre.org/techniques/T1213/) Data from Information Repositories |
| **Runs on** | Laptop browser (portal) |
| **Top rule** | 110501 (level 10) |
| **Rules** | [`wazuh/rules/pp-050-uc05_record_harvesting_rules.xml`](../../wazuh/rules/pp-050-uc05_record_harvesting_rules.xml) |
| **Regression cases** | [`tests/cases/uc05.json`](../../tests/cases/uc05.json) |

## Why it matters

Pilgrim records hold passport numbers and phone numbers, which are prime material for visa fraud and fake-Hajj scams. The biggest risk is an authorised insider quietly collecting records, and access control cannot stop someone who is allowed in.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)
- CDB list: [`wazuh/lists/pp-bulk-reviewers`](../../wazuh/lists/pp-bulk-reviewers)

## Detection logic

- 110501: the same account opens 12 *different* records in 3 minutes (`different_field pilgrim_id`). Re-opening one record does not count. A case handler works 3-5 records in that time.
- 110502: the same account is denied 5 records in 2 minutes. Someone is walking record IDs that are not theirs (an IDOR attempt); the portal blocks it and the SIEM reports it.

### Rules (2 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110501 | 10 | UC05 Record harvesting: `$(username)` [`$(role)`] opened 12+ different pilgrim records in 3 minutes. | T1213 |
| 110502 | 10 | UC05 Authorization probing: `$(username)` [`$(role)`] was denied 5+ pilgrim records in 2 minutes (IDOR attempt). | T1190 |

Built on the shared portal base rules 110014, 110015 in [`wazuh/rules/pp-000-portal_base_rules.xml`](../../wazuh/rules/pp-000-portal_base_rules.xml).

<details>
<summary>Rule XML</summary>

```xml
<rule id="110501" level="10" frequency="12" timeframe="180" ignore="300">
  <if_matched_sid>110014</if_matched_sid>
  <same_field>username</same_field>
  <different_field>pilgrim_id</different_field>
  <list field="username" lookup="not_match_key">etc/lists/pp-bulk-reviewers</list>
  <description>UC05 Record harvesting: $(username) [$(role)] opened 12+ different pilgrim records in 3 minutes.</description>
  <mitre>
    <id>T1213</id>
  </mitre>
  <group>pp_data_harvesting,</group>
</rule>

<rule id="110502" level="10" frequency="5" timeframe="120" ignore="300">
  <if_matched_sid>110015</if_matched_sid>
  <same_field>username</same_field>
  <description>UC05 Authorization probing: $(username) [$(role)] was denied 5+ pilgrim records in 2 minutes (IDOR attempt).</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>pp_authz_probing,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110501, level 10:** UC05 Record harvesting: staff.ops01 [staff] opened 12+ different pilgrim records in 3 minutes.

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"record_view","srcip":"192.168.20.31","username":"staff.ops01","role":"staff","pilgrim_id":"1011","record_agency":"AG-IN01","result":"allowed"}
```

**110502, level 10:** UC05 Authorization probing: pilgrim0042 [pilgrim] was denied 5+ pilgrim records in 2 minutes (IDOR attempt).

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"record_view","srcip":"203.0.113.55","username":"pilgrim0042","role":"pilgrim","pilgrim_id":"1047","record_agency":"AG-ID01","result":"denied"}
```

## How to test it live

Runs on: Laptop browser (portal).

1. Sign in as `staff.ops01` / `Staff#2026`, open **Records** and click 12 different names quickly, which gives 110501.
2. Sign in as `pilgrim0042`, then type `/records/1100`, `/records/1101` ... `/records/1104` in the address bar. Each returns 403 and the fifth fires 110502.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Approved bulk reviewers (e.g. during visa-processing peaks) are listed in `etc/lists/pp-bulk-reviewers`.
- Duplicate suppression: tuning rule 110022 absorbs the nginx 403/404 lines for refused record requests, which would otherwise raise the generic 31101 alert next to UC05 (regression case UC05-05).
- `ignore="300"` avoids repeat alerts while one investigation is open.

## Regression cases

5 cases (2 positive, 3 negative) in [`tests/cases/uc05.json`](../../tests/cases/uc05.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC05-01 | positive | Staff opens 12 different pilgrim records in minutes -> 110501 |
| UC05-02 | negative | Same record re-opened 12 times (no alert) |
| UC05-03 | negative | Approved bulk reviewer during a visa peak (no alert) |
| UC05-04 | positive | Pilgrim walks other pilgrims' record IDs and is denied 5 times -> 110502 |
| UC05-05 | negative | Tuning: nginx 403 for a refused record is absorbed (no duplicate 31101 alert) |

## How to improve it

- Weight sensitive views (passport shown in full) higher than list views.
- Correlate harvesting with a following export (UC09) as a level-15 data-theft chain.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
