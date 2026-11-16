[All use cases](../../README.md#the-use-cases) · Previous: [UC23](../UC23-usb-exfiltration/README.md) · Next: [UC25](../UC25-ransomware-behaviour/README.md)

# UC24: Command-and-control or data theft over DNS

| | |
|---|---|
| **Tactic** | Command and Control / Exfiltration |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/) Exfiltration Over Alternative Protocol, [T1071.004](https://attack.mitre.org/techniques/T1071/004/) DNS, [T1572](https://attack.mitre.org/techniques/T1572/) Protocol Tunneling |
| **Runs on** | Windows 10 VM |
| **Top rule** | 112402 (level 12) |
| **Rules** | [`wazuh/rules/pp-240-uc24_dns_tunnel_rules.xml`](../../wazuh/rules/pp-240-uc24_dns_tunnel_rules.xml) |
| **Regression cases** | [`tests/cases/uc24.json`](../../tests/cases/uc24.json) |

## Why it matters

Booking and visa systems sit behind firewalls that still allow DNS everywhere. Malware uses DNS when the web proxy blocks it, and it can carry pilgrim records out a few bytes at a time without any file transfer.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Sysmon DNS query (event 22) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 112401 (2, silent): a DNS query with a label of 30+ characters, where tunnels hide encoded data.
- 112402 (12): 20 or more DIFFERENT long-label queries from the same process within 60 seconds.
- 112403 (10): a lookup of a tunnelling, dynamic-DNS or out-of-band testing service (ngrok, trycloudflare, duckdns, no-ip, interactsh/oast, Burp Collaborator, dnslog, webhook.site...).

### Rules (2 alerting, 1 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 112401 | 2 (silent) | UC24 DNS query with a long label (classification): `$(win.eventdata.queryName)` | T1071.004 |
| 112402 | 12 | UC24 Possible DNS tunnel on `$(win.system.computer)`: `$(win.eventdata.image)` sent 20+ unique long DNS names in 60 seconds, e.g. `$(win.eventdata.queryName)` | T1071.004, T1048 |
| 112403 | 10 | UC24 Lookup of a tunnelling or out-of-band service on `$(win.system.computer)`: `$(win.eventdata.queryName)` by `$(win.eventdata.image)` | T1572, T1071.004 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="112401" level="2">
  <if_sid>61650</if_sid>
  <field name="win.eventdata.queryName" type="pcre2">(?i)^(?!.*\.(amazonaws\.com|cloudapp\.net|azurewebsites\.net|trafficmanager\.net|akamaiedge\.net|akamaized\.net|cloudfront\.net|sophosxl\.net|googleusercontent\.com)$)(.*\.)?[a-z0-9_-]{30,}\.</field>
  <description>UC24 DNS query with a long label (classification): $(win.eventdata.queryName)</description>
  <mitre>
    <id>T1071.004</id>
  </mitre>
  <group>pp_dns_long,</group>
</rule>

<rule id="112402" level="12" frequency="20" timeframe="60" ignore="300">
  <if_group>pp_dns_long</if_group>
  <if_matched_sid>112401</if_matched_sid>
  <same_field>win.eventdata.image</same_field>
  <different_field>win.eventdata.queryName</different_field>
  <description>UC24 Possible DNS tunnel on $(win.system.computer): $(win.eventdata.image) sent 20+ unique long DNS names in 60 seconds, e.g. $(win.eventdata.queryName)</description>
  <mitre>
    <id>T1071.004</id>
    <id>T1048</id>
  </mitre>
  <group>pp_dns_tunnel,</group>
</rule>

<rule id="112403" level="10">
  <if_sid>61650</if_sid>
  <field name="win.eventdata.queryName" type="pcre2">(?i)(^|\.)(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|duckdns\.org|no-ip\.(org|com|biz)|ddns\.net|serveo\.net|loca\.lt|localtunnel\.me|pagekite\.me|oast\.(fun|pro|live|site|online|me)|interact\.sh|burpcollaborator\.net|dnslog\.cn|requestbin\.net|pipedream\.net|webhook\.site)\.?$</field>
  <description>UC24 Lookup of a tunnelling or out-of-band service on $(win.system.computer): $(win.eventdata.queryName) by $(win.eventdata.image)</description>
  <mitre>
    <id>T1572</id>
    <id>T1071.004</id>
  </mitre>
  <group>pp_dns_tunnel,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**112402, level 12:** UC24 Possible DNS tunnel on WIN10-LAB: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe sent 20+ unique long DNS names in 60 seconds, e.g. b3f0c7f6bb763af1be91d9e74eabfeb199dc1f1f.exfil.example.com

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "22"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:10:00.000", "processGuid": "{11111111-2222-3333-4444-55555555555a}", "processId": "6400", "queryName": "b3f0c7f6bb763af1be91d9e74eabfeb199dc1f1f.exfil.example.com", "queryStatus": "9003", "queryResults": "-", "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "user": "WIN10-LAB\\\\ahmed"}}}
```

**112403, level 10:** UC24 Lookup of a tunnelling or out-of-band service on WIN10-LAB: 2f1c-198-51-100-9.ngrok-free.app by C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "22"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:10:00.000", "processGuid": "{11111111-2222-3333-4444-55555555555a}", "processId": "6400", "queryName": "2f1c-198-51-100-9.ngrok-free.app", "queryStatus": "9003", "queryResults": "-", "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "user": "WIN10-LAB\\\\ahmed"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM, in PowerShell (it only looks up names that do not exist):
2. `1..25 | % { $l = -join (1..40 | % { [char](Get-Random -InputObject (48..57 + 97..122)) }); Resolve-DnsName "$l.example.com" -ErrorAction SilentlyContinue }` gives 112402.
3. `Resolve-DnsName pilgrimlab.oast.fun -ErrorAction SilentlyContinue` gives 112403.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Long labels alone are silent: CDNs and cloud load balancers use them, so only a burst of unique ones from one process alerts. AWS, Azure, Akamai, CloudFront, Sophos and Google user-content names are excluded (case UC24-05).
- Repeating the same long name (cache refresh) is not a burst (case UC24-04).

## Regression cases

5 cases (3 positive, 2 negative) in [`tests/cases/uc24.json`](../../tests/cases/uc24.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC24-01 | positive | 20 unique 40-character subdomains from one process in a minute -> 112402 |
| UC24-02 | positive | Lookup of an ngrok tunnel host -> 112403 |
| UC24-03 | positive | Lookup of an interactsh / OAST host -> 112403 |
| UC24-04 | negative | Same long name repeated 20 times (cache refresh, no burst) |
| UC24-05 | negative | Long AWS load-balancer names are excluded (no burst) |

## How to improve it

- Add DNS server logs so queries from devices without Sysmon are covered.
- Score label entropy in an integration script and feed the result back as a field.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
