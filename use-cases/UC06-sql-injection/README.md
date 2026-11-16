[All use cases](../../README.md#the-use-cases) · Previous: [UC05](../UC05-record-harvesting/README.md) · Next: [UC07](../UC07-web-tier-compromise/README.md)

# UC06: SQL injection attempts (edge and application)

| | |
|---|---|
| **Tactic** | Initial Access |
| **ATT&CK** | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application |
| **Runs on** | Laptop browser (portal) |
| **Top rule** | 110602 (level 12) |
| **Rules** | [`wazuh/rules/pp-060-uc06_sql_injection_rules.xml`](../../wazuh/rules/pp-060-uc06_sql_injection_rules.xml) |
| **Regression cases** | [`tests/cases/uc06.json`](../../tests/cases/uc06.json) |

## Why it matters

The public permit-status search is the portal's most exposed input. The portal uses parameterised queries, so injection fails, but every attempt is reconnaissance by someone targeting pilgrim data, and scanners hammer such pages during the season.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| nginx access log | `/var/log/nginx/access.log` on web01 (combined format) | Built-in `web-accesslog` |
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)
- CDB list: [`wazuh/lists/pp-trusted-ips`](../../wazuh/lists/pp-trusted-ips)

## Detection logic

- 110601 (edge): injection grammar in the URL, including URL-encoded forms: quote-plus-boolean tautologies, `UNION SELECT`, comment terminators after a quote, time-based functions, schema tables, stacked queries.
- 110602: 5 edge attempts from one IP in 60 s indicates an automated scanner.
- 110603 (application): the same grammar in the decoded `q` field, with no encoding tricks to hide behind.
- 110604: the injection was seen at the edge AND reached the application handler from the same IP within 30 s.
- Why not the built-in 31103: it matches a few literal strings and, on HTTP 200, ends as 31106 'attack returned 200 (success)', which is misleading for a parameterised app that simply answered 'no results'. Wazuh tries sibling rules highest level first, so these rules take precedence.

### Rules (5 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110601 | 8 | UC06 SQL injection attempt against the portal from `$(srcip)`: `$(url)` | T1190 |
| 110602 | 12 | UC06 Automated SQL injection scanning: 5+ injection attempts from `$(srcip)` in 60 seconds. | T1190 |
| 110603 | 10 | UC06 SQL injection attempt in the permit search parameter from `$(srcip)` (decoded at the application). | T1190 |
| 110604 | 11 | UC06 SQL injection from `$(srcip)` seen at the edge AND reaching the application search handler. | T1190 |
| 110605 | 12 | UC06 Automated SQL injection reaching the application: 5+ injection searches from `$(srcip)` in 60 seconds. | T1190 |

Built on the shared portal base rule 110016 in [`wazuh/rules/pp-000-portal_base_rules.xml`](../../wazuh/rules/pp-000-portal_base_rules.xml).

<details>
<summary>Rule XML</summary>

```xml
<rule id="110601" level="8">
  <if_sid>31100</if_sid>
  <url type="pcre2">(?i)(?:union(?:\s|\+|%20|%09|/\*.*?\*/)+(?:all(?:\s|\+|%20)+)?select)|(?:(?:'|%27)(?:\s|\+|%20)*(?:or|and)(?:\s|\+|%20)+(?:'|%27)?\w+(?:'|%27)?(?:\s|\+|%20)*(?:=|%3d|&lt;|%3c|&gt;|%3e|like))|(?:(?:'|%27)(?:\s|\+|%20)*(?:--|%2d%2d|#|%23|/\*|%2f%2a))|(?:(?:sleep|benchmark|pg_sleep)(?:\s|\+|%20)*(?:\(|%28))|(?:information_schema|sqlite_master)|(?:(?:;|%3b)(?:\s|\+|%20)*(?:drop|insert|update|delete|exec)(?:\s|\+|%20))</url>
  <list field="srcip" lookup="not_address_match_key">etc/lists/pp-trusted-ips</list>
  <description>UC06 SQL injection attempt against the portal from $(srcip): $(url)</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>pp_sqli,pp_sqli_edge,attack,sql_injection,</group>
</rule>

<rule id="110602" level="12" frequency="5" timeframe="60" ignore="300">
  <if_matched_group>pp_sqli_edge</if_matched_group>
  <same_srcip />
  <description>UC06 Automated SQL injection scanning: 5+ injection attempts from $(srcip) in 60 seconds.</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>pp_sqli,attack,sql_injection,</group>
</rule>

<rule id="110603" level="10">
  <if_sid>110016</if_sid>
  <field name="q" type="pcre2">(?i)(?:\bunion\s+(?:all\s+)?select\b)|(?:'\s*(?:or|and)\s+'?\w+'?\s*(?:=|&lt;|&gt;|\blike\b))|(?:'\s*(?:--|#|/\*))|(?:\b(?:sleep|benchmark|pg_sleep)\s*\()|(?:\binformation_schema\b|\bsqlite_master\b)|(?:;\s*(?:drop|insert|update|delete|exec)\s)</field>
  <description>UC06 SQL injection attempt in the permit search parameter from $(srcip) (decoded at the application).</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>pp_sqli,pp_sqli_app,attack,sql_injection,</group>
</rule>

<rule id="110604" level="11" timeframe="30">
  <if_sid>110601</if_sid>
  <if_matched_sid>110603</if_matched_sid>
  <same_srcip />
  <description>UC06 SQL injection from $(srcip) seen at the edge AND reaching the application search handler.</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>pp_sqli,pp_sqli_edge,attack,sql_injection,</group>
</rule>

<rule id="110605" level="12" frequency="5" timeframe="60" ignore="300">
  <if_matched_sid>110604</if_matched_sid>
  <same_srcip />
  <description>UC06 Automated SQL injection reaching the application: 5+ injection searches from $(srcip) in 60 seconds.</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>pp_sqli,attack,sql_injection,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110602, level 12:** UC06 Automated SQL injection scanning: 5+ injection attempts from 203.0.113.61 in 60 seconds.

```
203.0.113.61 - - [10/Nov/2026:20:15:03 +0300] "GET /permits?q=%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 1532 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

**110601, level 8:** UC06 SQL injection attempt against the portal from 203.0.113.60: /permits?q=%27%20OR%20%271%27%3D%271

```
203.0.113.60 - - [10/Nov/2026:20:15:03 +0300] "GET /permits?q=%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 1532 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

## How to test it live

Runs on: Laptop browser (portal).

1. Open **Permit status** and search for `x' OR 'a'='a`.
2. The portal answers 'No permit found' (parameterised query). Wazuh shows 110603 then 110604.
3. Wait 30 seconds. In the browser's address bar open `http://<web01-ip>/?q=x' UNION SELECT NULL--` and press F5 four more times within a minute (5 requests in all), which gives 110602. This burst is counted at the edge only: requests that also reach the search handler become 110604 instead.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- The patterns require injection *structure*, not keywords: 'Abdullah D'Or' or 'Union Travel' do not match (regression case UC06-05).
- Approved internal scanners are allowlisted in `pp-trusted-ips`.

## Regression cases

6 cases (5 positive, 1 negative) in [`tests/cases/uc06.json`](../../tests/cases/uc06.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC06-01 | positive | Encoded tautology in the URL -> 110601 |
| UC06-02 | positive | UNION SELECT and time-based probes, 5 in a row from one IP -> 110602 |
| UC06-03 | positive | Injection grammar in the decoded search parameter -> 110603 |
| UC06-04 | positive | Same request seen by the app and then the edge -> 110604 |
| UC06-05 | negative | Legitimate searches with an apostrophe or the word union (no alert) |
| UC06-06 | positive | Found live: 5 injection searches seen by app then edge -> burst 110605 |

## How to improve it

- Active response to block the IP on 110602.
- Add a WAF (ModSecurity CRS) and ingest its audit log for a third detection layer.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
