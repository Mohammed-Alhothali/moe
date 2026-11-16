[All use cases](../../README.md#the-use-cases) · Previous: [UC07](../UC07-web-tier-compromise/README.md) · Next: [UC09](../UC09-bulk-export/README.md)

# UC08: Package price override abuse (insider fraud)

| | |
|---|---|
| **Tactic** | Impact |
| **ATT&CK** | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) Stored Data Manipulation |
| **Runs on** | Laptop browser (portal) |
| **Top rule** | 110803 (level 14) |
| **Rules** | [`wazuh/rules/pp-080-uc08_price_override_rules.xml`](../../wazuh/rules/pp-080-uc08_price_override_rules.xml) |
| **Regression cases** | [`tests/cases/uc08.json`](../../tests/cases/uc08.json) |

## Why it matters

Staff can override a package price for VIP guests or compensation. That power is a classic insider-fraud path, for example selling a 45,000 SAR VIP package to a friend for 4,500. The app allows it by design, so governance is a detective control.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)
- CDB list: [`wazuh/lists/pp-price-approvers`](../../wazuh/lists/pp-price-approvers)

## Detection logic

- 110801: discount of 30% or more (regex `^(?:[3-9]\d|100)$` on `discount_pct`, since Wazuh 4.x has no numeric comparison).
- 110802: override by an account not on the finance approvers CDB list.
- 110803 (level 14): both of the above.
- 110804: 4 overrides by one account within 10 minutes (counted through group `pp_price_override`).
- Sibling order matters: Wazuh tries the higher-level sibling first, so the non-approver path (12, then child 14) is evaluated before the plain large-discount rule (10).

### Rules (4 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110801 | 10 | UC08 Large discount: `$(username)` cut `$(package_id)` by `$(discount_pct)`% (`$(list_price)` to `$(new_price)` SAR), reason: `$(reason_code)`. | T1565.001 |
| 110802 | 12 | UC08 Unauthorized price override: `$(username)` is not a finance approver (`$(package_id)` set to `$(new_price)` SAR). | T1565.001 |
| 110803 | 14 | UC08 Unauthorized large discount: `$(username)` (not an approver) cut `$(package_id)` by `$(discount_pct)`% to `$(new_price)` SAR. | T1565.001 |
| 110804 | 12 | UC08 Repeated price overrides: `$(username)` made 4+ overrides in 10 minutes. | T1565.001 |

Built on the shared portal base rule 110017 in [`wazuh/rules/pp-000-portal_base_rules.xml`](../../wazuh/rules/pp-000-portal_base_rules.xml).

<details>
<summary>Rule XML</summary>

```xml
<rule id="110801" level="10">
  <if_sid>110017</if_sid>
  <field name="discount_pct" type="pcre2">^(?:[3-9]\d|100)$</field>
  <description>UC08 Large discount: $(username) cut $(package_id) by $(discount_pct)% ($(list_price) to $(new_price) SAR), reason: $(reason_code).</description>
  <mitre>
    <id>T1565.001</id>
  </mitre>
  <group>pp_price_override,</group>
</rule>

<rule id="110802" level="12">
  <if_sid>110017</if_sid>
  <list field="username" lookup="not_match_key">etc/lists/pp-price-approvers</list>
  <description>UC08 Unauthorized price override: $(username) is not a finance approver ($(package_id) set to $(new_price) SAR).</description>
  <mitre>
    <id>T1565.001</id>
  </mitre>
  <group>pp_price_override,</group>
</rule>

<rule id="110803" level="14">
  <if_sid>110802</if_sid>
  <field name="discount_pct" type="pcre2">^(?:[3-9]\d|100)$</field>
  <description>UC08 Unauthorized large discount: $(username) (not an approver) cut $(package_id) by $(discount_pct)% to $(new_price) SAR.</description>
  <mitre>
    <id>T1565.001</id>
  </mitre>
  <group>pp_price_override,</group>
</rule>

<rule id="110804" level="12" frequency="4" timeframe="600" ignore="600">
  <if_matched_group>pp_price_override</if_matched_group>
  <same_field>username</same_field>
  <description>UC08 Repeated price overrides: $(username) made 4+ overrides in 10 minutes.</description>
  <mitre>
    <id>T1565.001</id>
  </mitre>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110802, level 12:** UC08 Unauthorized price override: staff.ops02 is not a finance approver (VIP-1448 set to 40500 SAR).

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"price_override","srcip":"192.168.20.40","username":"staff.ops02","role":"staff","package_id":"VIP-1448","list_price":"45000","new_price":"40500","discount_pct":"10","reason_code":"GOODWILL","booking_ref":"BK-77812"}
```

**110801, level 10:** UC08 Large discount: fin.approver01 cut VIP-1448 by 35% (45000 to 29250 SAR), reason: GOODWILL.

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"price_override","srcip":"192.168.20.40","username":"fin.approver01","role":"staff","package_id":"VIP-1448","list_price":"45000","new_price":"29250","discount_pct":"35","reason_code":"GOODWILL","booking_ref":"BK-77812"}
```

## How to test it live

Runs on: Laptop browser (portal).

1. Sign in as `staff.ops02` / `Staff#2026`, open **Pricing**, choose the VIP package and set 4500, which gives 110803.
2. As `fin.approver01` / `Finance#2026`, apply 35% off, which gives 110801. Four quick overrides give 110804.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Approvers live in `etc/lists/pp-price-approvers`, owned by Finance, so no rule edits are needed when roles change.
- Small goodwill discounts by approvers stay as the level-3 audit trail (case UC08-05).

## Regression cases

5 cases (4 positive, 1 negative) in [`tests/cases/uc08.json`](../../tests/cases/uc08.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC08-01 | positive | Finance approver gives a 35% discount -> 110801 |
| UC08-02 | positive | Non-approver changes a price (10%) -> 110802 |
| UC08-03 | positive | Non-approver gives a 90% discount -> 110803 (level 14) |
| UC08-04 | positive | Approver makes 4 small overrides in 10 minutes -> 110804 |
| UC08-05 | negative | Approver gives a 10% goodwill discount (audit trail only) |

## How to improve it

- Require a `booking_ref` and correlate with the booking owner (overrides on one's own or relatives' bookings).
- Weekly SIEM report of overrides per staff member for the finance controller.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
