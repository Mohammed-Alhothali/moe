[All use cases](../../README.md#the-use-cases) · Previous: [UC03](../UC03-account-takeover/README.md) · Next: [UC05](../UC05-record-harvesting/README.md)

# UC04: Impossible travel

| | |
|---|---|
| **Tactic** | Initial Access |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |
| **Runs on** | web01 + phone + laptop VPN |
| **Top rule** | 110401 (level 12) |
| **Rules** | [`wazuh/rules/pp-040-uc04_impossible_travel_rules.xml`](../../wazuh/rules/pp-040-uc04_impossible_travel_rules.xml) |
| **Regression cases** | [`tests/cases/uc04.json`](../../tests/cases/uc04.json) |

## Why it matters

Pilgrims and agencies log in from every country, so 'login from abroad' means nothing here. Two countries within one hour on the same account does: the password is being used by someone else, usually through a proxy or a stolen session.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)
- CDB list: [`wazuh/lists/pp-vpn-egress`](../../wazuh/lists/pp-vpn-egress)

## Detection logic

- The portal resolves the client IP to a country (DB-IP Lite database, ip-api.com fallback) and logs it on every login.
- 110401: two successful logins for the same `username` from different `country` values within 3600 s (`frequency=2`, `same_field username`, `different_field country`, counted through group `pp_login_success`).

### Rules (1 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110401 | 12 | UC04 Impossible travel: `$(username)` logged in from `$(country)` (`$(srcip)`) less than an hour after a login from another country. | T1078 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="110401" level="12" frequency="2" timeframe="3600">
  <if_matched_group>pp_login_success</if_matched_group>
  <same_field>username</same_field>
  <different_field>country</different_field>
  <list field="srcip" lookup="not_address_match_key">etc/lists/pp-vpn-egress</list>
  <description>UC04 Impossible travel: $(username) logged in from $(country) ($(srcip)) less than an hour after a login from another country.</description>
  <mitre>
    <id>T1078</id>
  </mitre>
  <group>pp_impossible_travel,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110401, level 12:** UC04 Impossible travel: pilgrim0042 logged in from NL (185.107.56.10) less than an hour after a login from another country.

```
Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"login_success","srcip":"185.107.56.10","username":"pilgrim0042","role":"pilgrim","country":"NL","session":"s-0042"}
```

## How to test it live

Runs on: web01 + phone + laptop VPN.

1. On web01: `sudo portal/deploy/start-uc04-tunnel.sh`. It prints a temporary `https://...trycloudflare.com` address that reaches only the sign-in pages.
2. On your phone (mobile data, Wi-Fi off) open `<address>/login` and sign in as `pilgrim0042`.
3. On the laptop, connect Proton VPN Free (any country) and sign in as the same account through the same address. This fires 110401.
4. Disconnect the VPN and stop the tunnel (Ctrl+C).

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- A pilgrim in India in the morning and in Jeddah six hours later does not fire: that is a flight, outside the 1-hour window.
- Corporate and campaign VPN exit IPs are skipped through `etc/lists/pp-vpn-egress`.
- Known limitation: neighbouring countries (e.g. SA-BH over the causeway) cannot be expressed as a pair in a Wazuh 4.x rule.

## Regression cases

3 cases (1 positive, 2 negative) in [`tests/cases/uc04.json`](../../tests/cases/uc04.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC04-01 | positive | Same account: Saudi Arabia, then the Netherlands within the hour -> 110401 |
| UC04-02 | negative | Two logins from the same country (no alert) |
| UC04-03 | negative | Second login via the corporate VPN exit (allowlisted, no alert) |

## How to improve it

- Have the portal compute travel speed between consecutive logins (km/h) and alert above about 900 km/h, which also handles neighbouring countries.
- Add ASN/hosting-provider enrichment to flag VPS and Tor exits.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
