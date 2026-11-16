[All use cases](../../README.md#the-use-cases) · Previous: [UC13](../UC13-registry-run-keys/README.md) · Next: [UC15](../UC15-privileged-groups/README.md)

# UC14: Persistence through a scheduled task

| | |
|---|---|
| **Tactic** | Persistence / Execution |
| **ATT&CK** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task |
| **Runs on** | Windows 10 VM |
| **Top rule** | 111401 (level 12) |
| **Rules** | [`wazuh/rules/pp-140-uc14_scheduled_task_rules.xml`](../../wazuh/rules/pp-140-uc14_scheduled_task_rules.xml) |
| **Regression cases** | [`tests/cases/uc14.json`](../../tests/cases/uc14.json) |

## Why it matters

Scheduled tasks give an attacker persistence and a way to run as SYSTEM. During the season, staff PCs run the same few vendor updaters; a new task that starts something from the user's folder is out of place.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Windows Security log, scheduled task created (4698) | `Security` channel, collected by the agent's default config; audit policy set by `windows/setup-windows.ps1` | Built-in `windows_eventchannel` |
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 111401: a task is created (4698) whose action runs from a user-writable folder or through a script host.
- 111402: `schtasks /create ... /tr` with the same kind of action, from Sysmon, for machines without 4698 auditing.

### Rules (2 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111401 | 12 | UC14 Suspicious scheduled task `$(win.eventdata.taskName)` created by `$(win.eventdata.subjectUserName)` on `$(win.system.computer)`. | T1053.005 |
| 111402 | 12 | UC14 schtasks created a task with a suspicious action on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1053.005 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111401" level="12">
  <if_sid>60228</if_sid>
  <field name="win.eventdata.taskContent" type="pcre2">(?i)\\+(AppData|Temp|Users\\+Public|Downloads|ProgramData)\\+|\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?\b|\bcmd(\.exe)?\s+/c</field>
  <description>UC14 Suspicious scheduled task $(win.eventdata.taskName) created by $(win.eventdata.subjectUserName) on $(win.system.computer).</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
  <group>pp_persistence,</group>
</rule>

<rule id="111402" level="12">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/create\b.*/tr\s+.*(\\+(AppData|Temp|Users\\+Public|Downloads|ProgramData)\\+|\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?\b|\bcmd(\.exe)?\s+/c)</field>
  <description>UC14 schtasks created a task with a suspicious action on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
  <group>pp_persistence,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111401, level 12:** UC14 Suspicious scheduled task \\Updater created by ahmed on WIN10-LAB.

```
{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "channel": "Security", "keywords": "0x8020000000000000", "computer": "WIN10-LAB", "eventID": "4698"}, "eventdata": {"subjectUserName": "ahmed", "subjectDomainName": "WIN10-LAB", "taskName": "\\\\Updater", "taskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Actions Context=\"Author\"><Exec><Command>C:\\\\Users\\\\ahmed\\\\AppData\\\\Roaming\\\\upd.exe</Command></Exec></Actions></Task>"}}}
```

**111402, level 12:** UC14 schtasks created a task with a suspicious action on WIN10-LAB: schtasks.exe /create /sc onlogon /tn Updater /tr \"powershell -w hidden -f C:\\Users\\Public\\u.ps1\"

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "1"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "processGuid": "{11111111-2222-3333-4444-555555555555}", "processId": "4242", "image": "C:\\\\Windows\\\\System32\\\\schtasks.exe", "fileVersion": "10.0.19041.1", "description": "-", "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation", "originalFileName": "schtasks.exe", "commandLine": "schtasks.exe /create /sc onlogon /tn Updater /tr \"powershell -w hidden -f C:\\\\Users\\\\Public\\\\u.ps1\"", "currentDirectory": "C:\\\\Users\\\\ahmed\\\\", "user": "WIN10-LAB\\\\ahmed", "logonGuid": "{11111111-2222-3333-4444-000000000001}", "logonId": "0x3e7a1", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "parentProcessGuid": "{11111111-2222-3333-4444-555555555554}", "parentProcessId": "4100", "parentImage": "C:\\\\Windows\\\\explorer.exe", "parentCommandLine": "C:\\\\Windows\\\\explorer.exe", "parentUser": "WIN10-LAB\\\\ahmed"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM: `schtasks /create /tn PilgrimLab /tr "C:\Users\Public\lab.exe" /sc once /st 23:59 /f` gives 111402 (Sysmon) and 111401 (4698).
2. Clean up: `schtasks /delete /tn PilgrimLab /f`.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Browser and driver updaters run from Program Files and do not match.
- Admin scripts belong in a protected folder (e.g. `C:\Scripts`, writable by Administrators only), outside these patterns.

## Regression cases

3 cases (2 positive, 1 negative) in [`tests/cases/uc14.json`](../../tests/cases/uc14.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC14-01 | positive | Task 4698 runs an EXE from AppData -> 111401 |
| UC14-02 | positive | schtasks /create with a hidden PowerShell action -> 111402 |
| UC14-03 | negative | Updater task in Program Files (no alert) |

## How to improve it

- Alert on tasks created remotely (4698 with a network logon session) as lateral movement.
- Compare new task names against a baseline list exported from a clean image.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
