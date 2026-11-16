[All use cases](../../README.md#the-use-cases) · Previous: [UC12](../UC12-lolbin-downloads/README.md) · Next: [UC14](../UC14-scheduled-tasks/README.md)

# UC13: Persistence through registry autorun keys

| | |
|---|---|
| **Tactic** | Persistence |
| **ATT&CK** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Registry Run Keys, [T1547.004](https://attack.mitre.org/techniques/T1547/004/) Winlogon Helper |
| **Runs on** | Windows 10 VM |
| **Top rule** | 111302 (level 12) |
| **Rules** | [`wazuh/rules/pp-130-uc13_registry_run_key_rules.xml`](../../wazuh/rules/pp-130-uc13_registry_run_key_rules.xml) |
| **Regression cases** | [`tests/cases/uc13.json`](../../tests/cases/uc13.json) |

## Why it matters

Malware on a staff PC wants to survive the reboot at the end of the shift. A Run key is the simplest way, and the value usually points to something in the user's profile or to a script host.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Sysmon registry value set (event 13) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 111301 (level 8): a value written under Run / RunOnce. It hangs under Wazuh's level-0 classifier 92300, which would otherwise absorb every Run-key event.
- 111303 (level 8): Winlogon `Userinit`/`Shell` or `Policies\Explorer\Run` changed (keys 92300 does not cover).
- 111302 (level 12): either of them launches something from a user-writable folder or through a script host (powershell, mshta, wscript, rundll32, `cmd /c`).

### Rules (3 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111301 | 8 | UC13 Autorun registry value set on `$(win.system.computer)` by `$(win.eventdata.image)`: `$(win.eventdata.targetObject)` | T1547.001 |
| 111302 | 12 | UC13 Malicious-looking autorun on `$(win.system.computer)`: `$(win.eventdata.targetObject)` = `$(win.eventdata.details)` | T1547.001 |
| 111303 | 8 | UC13 Logon autostart changed on `$(win.system.computer)` by `$(win.eventdata.image)`: `$(win.eventdata.targetObject)` | T1547.001, T1547.004 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111301" level="8">
  <if_sid>92300</if_sid>
  <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)\\(msiexec|OneDriveSetup|OneDrive|TrustedInstaller|setup[^\\]*)\.exe$</field>
  <description>UC13 Autorun registry value set on $(win.system.computer) by $(win.eventdata.image): $(win.eventdata.targetObject)</description>
  <mitre>
    <id>T1547.001</id>
  </mitre>
  <group>pp_persistence,</group>
</rule>

<rule id="111302" level="12">
  <if_sid>111301, 111303</if_sid>
  <field name="win.eventdata.details" type="pcre2">(?i)\\+(AppData|Temp|Users\\+Public|ProgramData|Downloads)\\+|\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?\b|\bcmd(\.exe)?\s+/c</field>
  <description>UC13 Malicious-looking autorun on $(win.system.computer): $(win.eventdata.targetObject) = $(win.eventdata.details)</description>
  <mitre>
    <id>T1547.001</id>
  </mitre>
  <group>pp_persistence,</group>
</rule>

<rule id="111303" level="8">
  <if_group>sysmon_event_13</if_group>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)\\Policies\\+Explorer\\+Run\\+|\\Winlogon\\+(Userinit|Shell)$</field>
  <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)\\(msiexec|TrustedInstaller|setup[^\\]*)\.exe$</field>
  <description>UC13 Logon autostart changed on $(win.system.computer) by $(win.eventdata.image): $(win.eventdata.targetObject)</description>
  <mitre>
    <id>T1547.001</id>
    <id>T1547.004</id>
  </mitre>
  <group>pp_persistence,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111302, level 12:** UC13 Malicious-looking autorun on WIN10-LAB: HKU\\S-1-5-21-1111111111-2222222222-3333333333-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater = C:\\Users\\ahmed\\AppData\\Roaming\\upd.exe

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "13"}, "eventdata": {"eventType": "SetValue", "targetObject": "HKU\\\\S-1-5-21-1111111111-2222222222-3333333333-1001\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater", "details": "C:\\\\Users\\\\ahmed\\\\AppData\\\\Roaming\\\\upd.exe", "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "user": "WIN10-LAB\\\\ahmed"}}}
```

**111301, level 8:** UC13 Autorun registry value set on WIN10-LAB by C:\\Program Files\\Zoom\\bin\\Zoom.exe: HKU\\S-1-5-21-1111111111-2222222222-3333333333-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Zoom

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "13"}, "eventdata": {"eventType": "SetValue", "targetObject": "HKU\\\\S-1-5-21-1111111111-2222222222-3333333333-1001\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Zoom", "details": "\"C:\\\\Program Files\\\\Zoom\\\\bin\\\\Zoom.exe\" --autostart", "image": "C:\\\\Program Files\\\\Zoom\\\\bin\\\\Zoom.exe", "user": "WIN10-LAB\\\\ahmed"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM: `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PilgrimLab /t REG_SZ /d "C:\Users\Public\lab.exe" /f` gives 111302 (the file does not need to exist).
2. Clean up: `reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PilgrimLab /f`.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Installers (msiexec, setup programs, OneDrive) are excluded by process image with `negate="yes"` (case UC13-03).
- Software in Program Files only reaches the medium rules; level 12 needs a suspicious target.

## Regression cases

5 cases (4 positive, 1 negative) in [`tests/cases/uc13.json`](../../tests/cases/uc13.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC13-01 | positive | Run key launching an EXE from AppData -> 111302 |
| UC13-02 | positive | Run key written by a normal application in Program Files -> 111301 (medium) |
| UC13-03 | negative | Installer (msiexec) writes a Run key (no alert) |
| UC13-04 | positive | Winlogon Userinit hijacked to also start a file from Users\Public -> 111302 |
| UC13-05 | positive | Policies\Explorer\Run entry pointing at Program Files -> 111303 (medium) |

## How to improve it

- Add the Startup folder (Sysmon event 11 on `\Start Menu\Programs\Startup\`).
- Hash-check the target file with the VirusTotal integration.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
