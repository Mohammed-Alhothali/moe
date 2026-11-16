[All use cases](../../README.md#the-use-cases) · Previous: [UC18](../UC18-cron-persistence/README.md) · Next: [UC20](../UC20-credential-theft/README.md)

# UC19: Defence evasion: Defender weakened, event logs wiped

| | |
|---|---|
| **Tactic** | Defense Evasion |
| **ATT&CK** | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Clear Windows Event Logs, [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Disable or Modify Tools |
| **Runs on** | Windows 10 VM |
| **Top rule** | 111910 (level 15) |
| **Rules** | [`wazuh/rules/pp-190-uc19_defense_evasion_rules.xml`](../../wazuh/rules/pp-190-uc19_defense_evasion_rules.xml) |
| **Regression cases** | [`tests/cases/uc19.json`](../../tests/cases/uc19.json) |

## Why it matters

Before ransomware or data theft, intruders switch off the antivirus, exclude their staging folder and wipe the logs. Each step on its own can be an admin mistake; together they are an attack in progress.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Microsoft Defender operational log | `Microsoft-Windows-Windows Defender/Operational` (shared `agent.conf`) | Built-in `windows_eventchannel` |
| Windows Security log, audit log cleared (1102) | `Security` channel, collected by the agent's default config; audit policy set by `windows/setup-windows.ps1` | Built-in `windows_eventchannel` |
| Windows System log, log cleared (104) | `System` channel, collected by the agent's default config | Built-in `windows_eventchannel` |
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 111901 (10): real-time / antivirus / antispyware protection turned off (Defender 5001, 5010, 5012).
- 111902 (12): a Defender exclusion was added (5007). 111903 (13): the exclusion is a whole drive, a user-writable folder, an executable or script extension, or a script host.
- 111904 (12): Tamper Protection blocked a change that would weaken Defender (5013 with a Disable* value going to 1, or an exclusion); found live: switching protection back on logs 5013 `0 -> 0`, which no longer alerts. 111905 (12): command lines that add exclusions, set Defender `Disable*` policy values or stop its services. 111906 (13): Wazuh's own Set-MpPreference rules re-raised in this use case.
- 111907/111908 (12/10): the Security log or another log was cleared. 111909 (12): `wevtutil cl`, `Clear-EventLog`...
- 111910 (15): logs wiped within 30 minutes AFTER Defender was weakened on the same host.
- Wazuh keeps the spaces in Defender's field names and only lower-cases the first letter, so the rules read `win.eventdata.new Value`.

### Rules (10 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111901 | 10 | UC19 Microsoft Defender protection turned off on `$(win.system.computer)` (event `$(win.system.eventID)`) | T1562.001 |
| 111902 | 12 | UC19 Microsoft Defender exclusion added on `$(win.system.computer)`: `$(win.eventdata.new Value)` | T1562.001 |
| 111903 | 13 | UC19 High-risk Defender exclusion on `$(win.system.computer)` (drive, user-writable folder, script type or script host): `$(win.eventdata.new Value)` | T1562.001 |
| 111904 | 12 | UC19 Tamper Protection blocked an attempt to weaken Microsoft Defender on `$(win.system.computer)`: `$(win.eventdata.value)` | T1562.001 |
| 111905 | 12 | UC19 Command to disable or bypass Microsoft Defender on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1562.001 |
| 111906 | 13 | UC19 Defender protection switched off from PowerShell on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1562.001 |
| 111907 | 12 | UC19 Security event log cleared on `$(win.system.computer)` | T1070.001 |
| 111908 | 10 | UC19 A Windows event log was cleared on `$(win.system.computer)` (System event 104) | T1070.001 |
| 111909 | 12 | UC19 Command to wipe Windows event logs on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1070.001 |
| 111910 | 15 | UC19 Defence-evasion chain on `$(win.system.computer)`: Defender was weakened, then event logs were wiped within 30 minutes | T1562.001, T1070.001 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111901" level="10">
  <if_sid>62100, 62101, 62102, 62157, 62159</if_sid>
  <field name="win.system.eventID">^5001$|^5010$|^5012$</field>
  <description>UC19 Microsoft Defender protection turned off on $(win.system.computer) (event $(win.system.eventID))</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>pp_defense_tamper,</group>
</rule>

<rule id="111902" level="12">
  <if_sid>62100, 62101, 62102</if_sid>
  <field name="win.system.eventID">^5007$</field>
  <field name="win.eventdata.new Value" type="pcre2">(?i)\\+Exclusions\\+(Paths|Extensions|Processes|IpAddresses)\\+</field>
  <description>UC19 Microsoft Defender exclusion added on $(win.system.computer): $(win.eventdata.new Value)</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>pp_defense_tamper,pp_defender_exclusion,</group>
</rule>

<rule id="111903" level="13">
  <if_group>pp_defender_exclusion</if_group>
  <field name="win.eventdata.new Value" type="pcre2">(?i)\\+Exclusions\\+Paths\\+([a-z]:\\*\s*=|.*\\+(Users\\+Public|AppData|Temp|Downloads|ProgramData|PerfLogs)(\\+|\s*=))|\\+Exclusions\\+Extensions\\+\.?(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi)\s*=|\\+Exclusions\\+Processes\\+.*\b(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript)\.exe</field>
  <description>UC19 High-risk Defender exclusion on $(win.system.computer) (drive, user-writable folder, script type or script host): $(win.eventdata.new Value)</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>pp_defense_tamper,</group>
</rule>

<rule id="111904" level="12">
  <if_sid>62100, 62101, 62102</if_sid>
  <field name="win.system.eventID">^5013$</field>
  <field name="win.eventdata.value" type="pcre2">(?i)\\Disable\w+\s*=\s*\S*\s*-(&amp;gt;|>)\s*0*[1-9]|\\Exclusions\\</field>
  <description>UC19 Tamper Protection blocked an attempt to weaken Microsoft Defender on $(win.system.computer): $(win.eventdata.value)</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>pp_defense_tamper,</group>
</rule>

<rule id="111905" level="12">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\b(add|set)-mppreference\b.*-exclusion(path|extension|process|ipaddress)\b|\\Windows Defender\b[^/]*\s/v\s+"?(Disable(AntiSpyware|AntiVirus|RealtimeMonitoring|BehaviorMonitoring|OnAccessProtection|ScanOnRealtimeEnable|IOAVProtection)|TamperProtection)\b|\bsc(\.exe)?\s+(stop|config|delete)\s+"?(WinDefend|WdNisSvc|WdFilter|WdBoot|Sense)\b|\b(Stop-Service|Set-Service)\b.*\bWinDefend\b</field>
  <description>UC19 Command to disable or bypass Microsoft Defender on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>pp_defense_tamper,</group>
</rule>

<rule id="111906" level="13">
  <if_sid>92008, 92009, 92010, 92011, 92012, 92013, 92014, 92015</if_sid>
  <description>UC19 Defender protection switched off from PowerShell on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>pp_defense_tamper,</group>
</rule>

<rule id="111907" level="12">
  <if_sid>63103, 60117</if_sid>
  <description>UC19 Security event log cleared on $(win.system.computer)</description>
  <mitre>
    <id>T1070.001</id>
  </mitre>
  <group>pp_log_clear,</group>
</rule>

<rule id="111908" level="10">
  <if_sid>63104</if_sid>
  <description>UC19 A Windows event log was cleared on $(win.system.computer) (System event 104)</description>
  <mitre>
    <id>T1070.001</id>
  </mitre>
  <group>pp_log_clear,</group>
</rule>

<rule id="111909" level="12">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\bwevtutil(\.exe)?(?:\\?")?\s+(cl|clear-log)\b|\b(Clear-EventLog|Remove-EventLog)\b|\.ClearLog\(|\bnteventlog\b.*\bcleareventlog\b</field>
  <description>UC19 Command to wipe Windows event logs on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1070.001</id>
  </mitre>
  <group>pp_log_clear,</group>
</rule>

<rule id="111910" level="15" timeframe="1800">
  <if_group>pp_log_clear</if_group>
  <if_matched_group>pp_defense_tamper</if_matched_group>
  <description>UC19 Defence-evasion chain on $(win.system.computer): Defender was weakened, then event logs were wiped within 30 minutes</description>
  <mitre>
    <id>T1562.001</id>
    <id>T1070.001</id>
  </mitre>
  <group>pp_evasion_chain,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111901, level 10:** UC19 Microsoft Defender protection turned off on WIN10-LAB (event 5001)

```
{"win": {"system": {"providerName": "Microsoft-Windows-Windows Defender", "providerGuid": "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}", "channel": "Microsoft-Windows-Windows Defender/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "5001"}, "eventdata": {"product Name": "Microsoft Defender Antivirus", "product Version": "4.18.24090.11"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. Windows Security > Virus & threat protection > Manage settings > Real-time protection **Off** gives 111901.
2. Same page > Exclusions > Add folder `C:\Users\Public` gives 111903.
3. In an elevated prompt, `wevtutil cl "Windows PowerShell"` clears one log. On its own that gives 111909 (command) and 111908 (System event 104); because Defender was weakened first, both escalate to 111910 (level 15).
4. Turn real-time protection back on and remove the exclusion.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Exclusions are split: 111902 for any exclusion, 111903 only for the risky kinds (case UC19-03 vs 04/05).
- Turning protection back on (5000) does not alert (case UC19-15).
- The chain needs both halves on the same agent; Wazuh correlates per agent by default.

## Regression cases

18 cases (15 positive, 3 negative) in [`tests/cases/uc19.json`](../../tests/cases/uc19.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC19-01 | positive | Real-time protection turned off (5001) -> 111901 |
| UC19-02 | positive | Antivirus scanning disabled logged as a warning (5012) -> 111901 |
| UC19-03 | positive | Exclusion added for a business folder -> 111902 |
| UC19-04 | positive | Exclusion added for C:\Users\Public -> 111903 |
| UC19-05 | positive | Whole-drive exclusion -> 111903 |
| UC19-06 | positive | Tamper Protection blocked a change (5013) -> 111904 |
| UC19-07 | positive | Add-MpPreference exclusion from PowerShell -> 111905 |
| UC19-08 | positive | reg.exe sets DisableAntiSpyware policy -> 111905 |
| UC19-09 | positive | sc stop WinDefend -> 111905 |
| UC19-10 | positive | Set-MpPreference disables real-time monitoring (Wazuh 92008 path) -> 111906 |
| UC19-11 | positive | Security log cleared (1102) -> 111907 |
| UC19-12 | positive | Windows PowerShell log cleared (System 104) -> 111908 |
| UC19-13 | positive | wevtutil cl from the command line -> 111909 |
| UC19-14 | positive | Defender turned off, then the Security log cleared -> 111910 |
| UC19-15 | negative | Real-time protection turned back on (5000) - no UC19 alert |
| UC19-16 | negative | Log cleared with no Defender change before it stays 111907 |
| UC19-17 | negative | Found live: turning protection back ON logs 5013 '= 0 -> 0' (no alert) |
| UC19-18 | positive | wevtutil cl typed in PowerShell (quoted path) -> 111909 |

## How to improve it

- Active response: re-enable real-time protection with `Set-MpPreference` when 111901 fires outside a change window.
- Forward the logs to the manager faster than an attacker can clear them (already true with the agent); add an alert when the agent itself stops reporting.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
