[All use cases](../../README.md#the-use-cases) · Previous: [UC06](../UC06-sql-injection/README.md) · Next: [UC08](../UC08-price-override-abuse/README.md)

# UC07: Web shell and web-tier compromise

| | |
|---|---|
| **Tactic** | Persistence / Execution |
| **ATT&CK** | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell, [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Web Shell |
| **Runs on** | Portal + web01 terminal |
| **Top rule** | 110703 (level 15) |
| **Rules** | [`wazuh/rules/pp-070-uc07_web_tier_compromise_rules.xml`](../../wazuh/rules/pp-070-uc07_web_tier_compromise_rules.xml) |
| **Regression cases** | [`tests/cases/uc07.json`](../../tests/cases/uc07.json) |

## Why it matters

A web shell gives an attacker a permanent foothold on the server that holds every pilgrim's data, and is the usual first step of ransomware and data theft against public portals.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Pilgrim portal audit log | `/var/log/pilgrim-portal/portal.log` on web01 (Wazuh agent, `log_format syslog`) | Custom: `pilgrim-portal` + JSON plugin (`wazuh/decoders/pp-pilgrim_portal_decoders.xml`) |
| File integrity monitoring | syscheck, realtime, on `/opt/pilgrim-portal/public` | Built-in syscheck |
| Linux audit (execve) | `/var/log/audit/audit.log`, key `pp_web_exec` (`portal/deploy/audit-pilgrim-portal.rules`) | Built-in `auditd` |

- Decoder: [`wazuh/decoders/pp-pilgrim_portal_decoders.xml`](../../wazuh/decoders/pp-pilgrim_portal_decoders.xml)
- CDB list: [`wazuh/lists/pp-web-allowed-binaries`](../../wazuh/lists/pp-web-allowed-binaries)

## Detection logic

- 110704 (early warning): the portal's upload allowlist rejected a server-side script or executable, for example `passport.php` posing as a scan.
- 110701: a script file (php, jsp, aspx, cgi, pl, py, sh ...) is created or modified in the web root. The portal is a Python app, so no executable code should ever appear there.
- 110702: a web service account (nginx `www-data` or the `portal` user) executes a program. Neither ever does in normal operation. auditd records it under key `pp_web_exec`; `ppid!=1` excludes systemd starting the service.
- 110703 (level 15): a script dropped, then the web tier executes commands within 15 minutes on the same server.

### Rules (4 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 110701 | 12 | UC07 Web shell suspected: server-side script `$(file)` appeared in the portal web root. | T1505.003 |
| 110702 | 10 | UC07 Web tier executed a command: `$(audit.exe)` run by uid `$(audit.euid)` (comm: `$(audit.command)`). | T1505.003, T1059.004 |
| 110703 | 15 | UC07 Web shell confirmed: a script was dropped in the web root and the web tier then executed `$(audit.exe)`. | T1505.003, T1059.004 |
| 110704 | 9 | UC07 Blocked upload of a server-side script or executable (`$(filename)`) by `$(username)` from `$(srcip)`. | T1505.003 |

Built on the shared portal base rule 110019 in [`wazuh/rules/pp-000-portal_base_rules.xml`](../../wazuh/rules/pp-000-portal_base_rules.xml).

<details>
<summary>Rule XML</summary>

```xml
<rule id="110701" level="12">
  <if_sid>550, 554</if_sid>
  <field name="file" type="pcre2">(?i)^/opt/pilgrim-portal/public/.+\.(?:php\d?|phtml|phar|pht|jspx?|aspx?|ashx|cgi|pl|py|sh)$</field>
  <description>UC07 Web shell suspected: server-side script $(file) appeared in the portal web root.</description>
  <mitre>
    <id>T1505.003</id>
  </mitre>
  <group>pp_webshell,</group>
</rule>

<rule id="110702" level="10">
  <if_sid>80700</if_sid>
  <field name="audit.key">^pp_web_exec$</field>
  <list field="audit.exe" lookup="not_match_key">etc/lists/pp-web-allowed-binaries</list>
  <description>UC07 Web tier executed a command: $(audit.exe) run by uid $(audit.euid) (comm: $(audit.command)).</description>
  <mitre>
    <id>T1505.003</id>
    <id>T1059.004</id>
  </mitre>
  <group>pp_webshell,</group>
</rule>

<rule id="110703" level="15" timeframe="900">
  <if_sid>110702</if_sid>
  <if_matched_sid>110701</if_matched_sid>
  <description>UC07 Web shell confirmed: a script was dropped in the web root and the web tier then executed $(audit.exe).</description>
  <mitre>
    <id>T1505.003</id>
    <id>T1059.004</id>
  </mitre>
  <group>pp_webshell,</group>
</rule>

<rule id="110704" level="9">
  <if_sid>110019</if_sid>
  <field name="result">^rejected$</field>
  <field name="ext" type="pcre2">(?i)^(?:php\d?|phtml|phar|pht|jspx?|aspx?|ashx|cgi|pl|py|sh|exe|dll|war)$</field>
  <description>UC07 Blocked upload of a server-side script or executable ($(filename)) by $(username) from $(srcip).</description>
  <mitre>
    <id>T1505.003</id>
  </mitre>
  <group>pp_webshell,pp_webshell_upload,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**110701, level 12:** UC07 Web shell suspected: server-side script /opt/pilgrim-portal/public/assets/uc07-test.php appeared in the portal web root.

```
File '/opt/pilgrim-portal/public/assets/uc07-test.php' added
```

**110702, level 10:** UC07 Web tier executed a command: /usr/bin/id run by uid 33 (comm: id).

```
type=SYSCALL msg=audit(1762800000.123:5501): arch=c000003e syscall=59 success=yes exit=0 a0=55d0c1a2b3c0 a1=55d0c1a2b400 a2=55d0c1a2b440 a3=0 items=2 ppid=4110 pid=4123 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="id" exe="/usr/bin/id" subj=unconfined key="pp_web_exec" type=EXECVE msg=audit(1762800000.123:5501): argc=1 a0="id" type=CWD msg=audit(1762800000.123:5501): cwd="/opt/pilgrim-portal/public" type=PATH msg=audit(1762800000.123:5501): item=0 name="/usr/bin/id" inode=1234 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
```

## How to test it live

Runs on: Portal + web01 terminal.

1. Portal: upload any small file renamed `passport.php` under **Documents**. It is blocked, which gives 110704.
2. web01: `sudo touch /opt/pilgrim-portal/public/static/uc07-test.php`, then wait until 110701 appears in the dashboard (about 10-15 seconds, FIM realtime). Do not delete the file yet.
3. web01: `sudo -u www-data /usr/bin/id`, which gives 110702 and, because the file alert came first, 110703 (level 15).
4. Clean up only after the alerts are on screen: `sudo rm /opt/pilgrim-portal/public/static/uc07-test.php`.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- FIM is scoped to the web root and to script extensions only (a CSS change does not fire, case UC07-04).
- Binaries the web tier legitimately needs can be added to `etc/lists/pp-web-allowed-binaries` without editing the rule.
- Deployments run as a CI user, never as `www-data`.

## Regression cases

6 cases (4 positive, 2 negative) in [`tests/cases/uc07.json`](../../tests/cases/uc07.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC07-01 | positive | Script file appears in the portal web root -> 110701 |
| UC07-02 | positive | Web service account (www-data) executes a program -> 110702 |
| UC07-03 | positive | Script dropped, then the web tier runs a command -> 110703 (level 15) |
| UC07-04 | negative | Static asset (CSS) change in the web root (no alert) |
| UC07-05 | positive | Upload allowlist blocks a .php disguised as a passport scan -> 110704 |
| UC07-06 | negative | Wrong document type (.docx) rejected - user error, not an attack (no alert) |

## How to improve it

- Active response: quarantine the file (move it out of the web root) on 110701.
- Hash new web-root files against a malware-hash CDB list or VirusTotal integration.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
