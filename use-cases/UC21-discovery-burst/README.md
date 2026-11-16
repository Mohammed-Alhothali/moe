[All use cases](../../README.md#the-use-cases) · Previous: [UC20](../UC20-credential-theft/README.md) · Next: [UC22](../UC22-remote-execution/README.md)

# UC21: Hands-on-keyboard discovery burst

| | |
|---|---|
| **Tactic** | Discovery |
| **ATT&CK** | [T1016](https://attack.mitre.org/techniques/T1016/) System Network Configuration Discovery, [T1033](https://attack.mitre.org/techniques/T1033/) System Owner/User Discovery, [T1069](https://attack.mitre.org/techniques/T1069/) Permission Groups Discovery, [T1069.002](https://attack.mitre.org/techniques/T1069/002/) Domain Groups, [T1082](https://attack.mitre.org/techniques/T1082/) System Information Discovery, [T1087](https://attack.mitre.org/techniques/T1087/) Account Discovery, [T1135](https://attack.mitre.org/techniques/T1135/) Network Share Discovery, [T1482](https://attack.mitre.org/techniques/T1482/) Domain Trust Discovery |
| **Runs on** | Windows 10 VM |
| **Top rule** | 112111 (level 13) |
| **Rules** | [`wazuh/rules/pp-210-uc21_discovery_burst_rules.xml`](../../wazuh/rules/pp-210-uc21_discovery_burst_rules.xml) |
| **Regression cases** | [`tests/cases/uc21.json`](../../tests/cases/uc21.json) |

## Why it matters

After the first foothold an intruder asks the machine who am I, where am I and who is admin, by running a quick series of built-in commands. Each one is normal for IT; five different ones in two minutes from one user is a person exploring.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 112101/112102/112103 classify discovery tools, read-only `net` verbs and `wmic`/`netsh ... show` at level 4 with `no_log`. Level 4 is needed because Wazuh's net.exe rules are level 3 and would claim the event first; `no_log` keeps them off the dashboard while they are still stored for correlation.
- 112109 is a funnel: every classified command passes through this one rule so it is stored exactly once. A rule with several parents sits in several places in Wazuh's rule tree, and group correlation stores the event once per place, so a 5-event threshold could fire after 2 events (found and fixed in the engine).
- 112110 (10): 5 commands, of different tools (`different_field originalFileName`), by the same user within 2 minutes.
- 112111 (13): the burst happens on a host that raised a phishing, PowerShell or LOLBin alert (UC10-UC12) in the last 30 min.
- 112104 (8): domain-level discovery (`nltest /domain_trusts`, `net group "domain admins" /domain`) alerts on its own.

### Rules (3 alerting, 4 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 112101 | 4 (silent) | UC21 Discovery command (classification): `$(win.eventdata.commandLine)` | T1033, T1082, T1016 |
| 112102 | 4 (silent) | UC21 Discovery command (classification): `$(win.eventdata.commandLine)` | T1087, T1069, T1135 |
| 112103 | 4 (silent) | UC21 Discovery command (classification): `$(win.eventdata.commandLine)` | T1082, T1016 |
| 112104 | 8 | UC21 Domain discovery on `$(win.system.computer)` by `$(win.eventdata.user)`: `$(win.eventdata.commandLine)` | T1482, T1069.002 |
| 112109 | 4 (silent) | UC21 Discovery command counted for burst detection: `$(win.eventdata.commandLine)` | T1033, T1082, T1087 |
| 112110 | 10 | UC21 Discovery burst on `$(win.system.computer)`: `$(win.eventdata.user)` ran 5+ different reconnaissance tools within 2 minutes | T1033, T1082, T1087 |
| 112111 | 13 | UC21 Discovery burst on `$(win.system.computer)` after a suspicious execution alert (UC10-UC12) on the same host in the last 30 minutes | T1033, T1082, T1087 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="112101" level="4">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^(whoami|hostname|ipconfig|sysinfo|tasklist|quser|qwinsta|query|arp|route|netstat|nltestrk|cmdkey|getmac|nbtstat)\.exe$</field>
  <field name="win.eventdata.parentImage" type="pcre2" negate="yes">(?i)\\(CcmExec|IntuneManagementExtension|AgentExecutor|net)\.exe$|\\ossec-agent\\+wazuh-agent\.exe$</field>
  <options>no_log</options>
  <description>UC21 Discovery command (classification): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1033</id>
    <id>T1082</id>
    <id>T1016</id>
  </mitre>
  <group>pp_discovery_tool,</group>
</rule>

<rule id="112102" level="4">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^net1?\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)^(?!.*\s/(add|delete|del)\b)(?!.*\suse\b).*\s(user|group|localgroup|accounts|view|share|session|config)\b</field>
  <field name="win.eventdata.parentImage" type="pcre2" negate="yes">(?i)\\(CcmExec|IntuneManagementExtension|AgentExecutor|net)\.exe$|\\ossec-agent\\+wazuh-agent\.exe$</field>
  <options>no_log</options>
  <description>UC21 Discovery command (classification): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1087</id>
    <id>T1069</id>
    <id>T1135</id>
  </mitre>
  <group>pp_discovery_tool,</group>
</rule>

<rule id="112103" level="4">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\bwmic(\.exe)?(?:\\?")?\s+(/node:\S+\s+)?(useraccount|group|computersystem|os|qfe|process|nicconfig|share|startup|product|service|logicaldisk)\b.*\b(get|list)\b|\bnetsh(\.exe)?(?:\\?")?\s+(wlan|interface|advfirewall|firewall)\b.*\bshow\b</field>
  <field name="win.eventdata.parentImage" type="pcre2" negate="yes">(?i)\\(CcmExec|IntuneManagementExtension|AgentExecutor|net)\.exe$|\\ossec-agent\\+wazuh-agent\.exe$</field>
  <options>no_log</options>
  <description>UC21 Discovery command (classification): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1082</id>
    <id>T1016</id>
  </mitre>
  <group>pp_discovery_tool,</group>
</rule>

<rule id="112104" level="8">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\bnltest(\.exe)?(?:\\?")?\s+.*/(dclist|domain_trusts|dsgetdc|trusted_domains|parentdomain)\b|\bnet1?(\.exe)?(?:\\?")?\s+group\s+"?(domain admins|enterprise admins|schema admins|domain controllers)"?.*/do(main)?\b</field>
  <description>UC21 Domain discovery on $(win.system.computer) by $(win.eventdata.user): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1482</id>
    <id>T1069.002</id>
  </mitre>
  <group>pp_discovery_domain,</group>
</rule>

<rule id="112109" level="4">
  <if_group>pp_discovery_tool</if_group>
  <options>no_log</options>
  <description>UC21 Discovery command counted for burst detection: $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1033</id>
    <id>T1082</id>
    <id>T1087</id>
  </mitre>
  <group>pp_discovery_hit,</group>
</rule>

<rule id="112110" level="10" frequency="5" timeframe="120" ignore="300">
  <if_group>pp_discovery_hit</if_group>
  <if_matched_sid>112109</if_matched_sid>
  <same_field>win.eventdata.user</same_field>
  <different_field>win.eventdata.originalFileName</different_field>
  <description>UC21 Discovery burst on $(win.system.computer): $(win.eventdata.user) ran 5+ different reconnaissance tools within 2 minutes</description>
  <mitre>
    <id>T1033</id>
    <id>T1082</id>
    <id>T1087</id>
  </mitre>
  <group>pp_recon_burst,</group>
</rule>

<rule id="112111" level="13" timeframe="1800">
  <if_group>pp_recon_burst</if_group>
  <if_matched_group>pp_execution</if_matched_group>
  <description>UC21 Discovery burst on $(win.system.computer) after a suspicious execution alert (UC10-UC12) on the same host in the last 30 minutes</description>
  <mitre>
    <id>T1033</id>
    <id>T1082</id>
    <id>T1087</id>
  </mitre>
  <group>pp_recon_after_exec,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**112110, level 10:** UC21 Discovery burst on WIN10-LAB: WIN10-LAB\\ahmed ran 5+ different reconnaissance tools within 2 minutes

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "1"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "processGuid": "{11111111-2222-3333-4444-555555555555}", "processId": "4242", "image": "C:\\\\Windows\\\\System32\\\\net.exe", "fileVersion": "10.0.19041.1", "description": "-", "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation", "originalFileName": "net.exe", "commandLine": "net localgroup administrators", "currentDirectory": "C:\\\\Users\\\\ahmed\\\\", "user": "WIN10-LAB\\\\ahmed", "logonGuid": "{11111111-2222-3333-4444-000000000001}", "logonId": "0x3e7a1", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "parentProcessGuid": "{11111111-2222-3333-4444-555555555554}", "parentProcessId": "4100", "parentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe", "parentCommandLine": "C:\\\\Windows\\\\system32\\\\cmd.exe", "parentUser": "WIN10-LAB\\\\ahmed"}}}
```

**112104, level 8:** UC21 Domain discovery on WIN10-LAB by WIN10-LAB\\ahmed: nltest /domain_trusts /all_trusts

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "1"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "processGuid": "{11111111-2222-3333-4444-555555555555}", "processId": "4242", "image": "C:\\\\Windows\\\\System32\\\\nltest.exe", "fileVersion": "10.0.19041.1", "description": "-", "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation", "originalFileName": "nltestrk.exe", "commandLine": "nltest /domain_trusts /all_trusts", "currentDirectory": "C:\\\\Users\\\\ahmed\\\\", "user": "WIN10-LAB\\\\ahmed", "logonGuid": "{11111111-2222-3333-4444-000000000001}", "logonId": "0x3e7a1", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "parentProcessGuid": "{11111111-2222-3333-4444-555555555554}", "parentProcessId": "4100", "parentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe", "parentCommandLine": "C:\\\\Windows\\\\system32\\\\cmd.exe", "parentUser": "WIN10-LAB\\\\ahmed"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM, in cmd: `whoami /all`, `hostname`, `ipconfig /all`, `systeminfo`, `net localgroup administrators`. The fifth command gives 112110.
2. Run the UC12 certutil test first and then the five commands, which gives 112111.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- A single command, or the same tool five times, stays silent (cases UC21-02, UC21-04).
- Inventory launched by SCCM or Intune is excluded by parent process (case UC21-07).
- Found live in the lab: the Wazuh agent's own SCA scan runs `net user` and `wmic useraccount ... get` as SYSTEM at every agent start, which fired 112110. The agent (`ossec-agent\wazuh-agent.exe`) is now excluded as a parent (case UC21-08).
- `net.exe` starts `net1.exe` with the same arguments; the child is not counted again, so repeated net commands never look like two different tools (case UC21-09).
- `net user ... /add` is left to Wazuh's own net.exe rules (case UC21-05) and to UC15.

## Regression cases

9 cases (4 positive, 5 negative) in [`tests/cases/uc21.json`](../../tests/cases/uc21.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC21-01 | positive | Five different discovery tools in a row -> 112110 on the fifth |
| UC21-02 | negative | A single discovery command stays silent (classified, counted, no alert) |
| UC21-03 | positive | Domain trust discovery -> 112104 |
| UC21-04 | negative | Admin re-runs ipconfig five times (same tool, no burst) |
| UC21-05 | positive | net user ... /add is left to Wazuh's net.exe rules (not swallowed by the classifier) |
| UC21-06 | positive | Burst after a LOLBin download on the same host -> 112111 |
| UC21-07 | negative | Inventory commands from the management agent (excluded) |
| UC21-08 | negative | Wazuh agent's own SCA scan (found live in the lab: wmic + net as SYSTEM) - no burst |
| UC21-09 | negative | Admin runs several net.exe queries; net1.exe children are not counted again - no burst |

## How to improve it

- Add PowerShell discovery cmdlets from script block logging (`Get-LocalGroupMember`, `Get-ADUser`).
- Raise to level 13 when the burst runs under a remote session (logon type 3 or 10).

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
