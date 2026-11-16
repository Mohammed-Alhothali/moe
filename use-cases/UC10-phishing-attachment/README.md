[All use cases](../../README.md#the-use-cases) · Previous: [UC09](../UC09-bulk-export/README.md) · Next: [UC11](../UC11-powershell-abuse/README.md)

# UC10: Phishing attachment runs (HTA, script, Office spawning a shell)

| | |
|---|---|
| **Tactic** | Initial Access / Execution |
| **ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) Malicious File, [T1218.005](https://attack.mitre.org/techniques/T1218/005/) Mshta, [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Spearphishing Attachment |
| **Runs on** | Windows 10 VM |
| **Top rule** | 111003 (level 13) |
| **Rules** | [`wazuh/rules/pp-100-uc10_phishing_attachment_rules.xml`](../../wazuh/rules/pp-100-uc10_phishing_attachment_rules.xml) |
| **Regression cases** | [`tests/cases/uc10.json`](../../tests/cases/uc10.json) |

## Why it matters

Agency and back-office staff live in their inbox during the season: visa updates, Nusuk invoices, permit confirmations and group rooming lists all arrive as attachments. Office now blocks internet macros, so attackers send HTA files, scripts and shortcuts instead. One click on a staff PC is the usual first step towards the booking systems and the passport share.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 111001: `mshta.exe` opens an HTA from Downloads, Temp, the browser cache or the Outlook cache, or straight from a URL.
- 111002: `wscript`/`cscript` runs a `.js/.jse/.vbs/.vbe/.wsf` file from those same download locations.
- 111003: Word, Excel, PowerPoint, Outlook or OneNote starts a shell, script host or LOLBin (`cmd`, `powershell`, `mshta`, `rundll32`, `certutil`...).
- Every process rule hangs under 61603 and under Wazuh's level-0 classifiers 92025/92028/92042/92069, because Wazuh tries level-0 rules first and they would otherwise absorb the event (engine note in the README).

### Rules (3 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111001 | 12 | UC10 Phishing attachment: mshta.exe opened an HTA from a mail/download location on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1566.001, T1218.005 |
| 111002 | 12 | UC10 Phishing attachment: script host ran a downloaded script on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1566.001, T1204.002 |
| 111003 | 13 | UC10 Office application started `$(win.eventdata.image)` on `$(win.system.computer)` (parent `$(win.eventdata.parentImage)`) - malicious document likely. | T1566.001, T1204.002 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111001" level="12">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\mshta\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\\+(Downloads|AppData\\+Local\\+Temp|INetCache|Content\.Outlook)\\+|https?://</field>
  <description>UC10 Phishing attachment: mshta.exe opened an HTA from a mail/download location on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1566.001</id>
    <id>T1218.005</id>
  </mitre>
  <group>pp_phishing,pp_execution,</group>
</rule>

<rule id="111002" level="12">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\[cw]script\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\\+(Downloads|AppData\\+Local\\+Temp|INetCache|Content\.Outlook)\\+[^"]+\.(js|jse|vbs|vbe|wsf|hta)\b</field>
  <description>UC10 Phishing attachment: script host ran a downloaded script on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1566.001</id>
    <id>T1204.002</id>
  </mitre>
  <group>pp_phishing,pp_execution,</group>
</rule>

<rule id="111003" level="13">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(winword|excel|powerpnt|outlook|onenote|msaccess|mspub)\.exe$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$</field>
  <description>UC10 Office application started $(win.eventdata.image) on $(win.system.computer) (parent $(win.eventdata.parentImage)) - malicious document likely.</description>
  <mitre>
    <id>T1566.001</id>
    <id>T1204.002</id>
  </mitre>
  <group>pp_phishing,pp_execution,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111001, level 12:** UC10 Phishing attachment: mshta.exe opened an HTA from a mail/download location on WIN10-LAB: \"C:\\Windows\\System32\\mshta.exe\" \"C:\\Users\\ahmed\\Downloads\\Hajj_visa_update.hta\"

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "1"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "processGuid": "{11111111-2222-3333-4444-555555555555}", "processId": "4242", "image": "C:\\\\Windows\\\\System32\\\\mshta.exe", "fileVersion": "10.0.19041.1", "description": "-", "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation", "originalFileName": "MSHTA.EXE", "commandLine": "\"C:\\\\Windows\\\\System32\\\\mshta.exe\" \"C:\\\\Users\\\\ahmed\\\\Downloads\\\\Hajj_visa_update.hta\"", "currentDirectory": "C:\\\\Users\\\\ahmed\\\\", "user": "WIN10-LAB\\\\ahmed", "logonGuid": "{11111111-2222-3333-4444-000000000001}", "logonId": "0x3e7a1", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "parentProcessGuid": "{11111111-2222-3333-4444-555555555554}", "parentProcessId": "4100", "parentImage": "C:\\\\Windows\\\\explorer.exe", "parentCommandLine": "C:\\\\Windows\\\\explorer.exe", "parentUser": "WIN10-LAB\\\\ahmed"}}}
```

**111002, level 12:** UC10 Phishing attachment: script host ran a downloaded script on WIN10-LAB: \"C:\\Windows\\System32\\WScript.exe\" \"C:\\Users\\ahmed\\AppData\\Local\\Temp\\Temp1_invoice.zip\\Nusuk_invoice.js\"

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "1"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "processGuid": "{11111111-2222-3333-4444-555555555555}", "processId": "4242", "image": "C:\\\\Windows\\\\System32\\\\wscript.exe", "fileVersion": "10.0.19041.1", "description": "-", "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation", "originalFileName": "wscript.exe", "commandLine": "\"C:\\\\Windows\\\\System32\\\\WScript.exe\" \"C:\\\\Users\\\\ahmed\\\\AppData\\\\Local\\\\Temp\\\\Temp1_invoice.zip\\\\Nusuk_invoice.js\"", "currentDirectory": "C:\\\\Users\\\\ahmed\\\\", "user": "WIN10-LAB\\\\ahmed", "logonGuid": "{11111111-2222-3333-4444-000000000001}", "logonId": "0x3e7a1", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "parentProcessGuid": "{11111111-2222-3333-4444-555555555554}", "parentProcessId": "4100", "parentImage": "C:\\\\Windows\\\\explorer.exe", "parentCommandLine": "C:\\\\Windows\\\\explorer.exe", "parentUser": "WIN10-LAB\\\\ahmed"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM, open Notepad and save this as `C:\Users\<you>\Downloads\lab.hta`: `<html><body>Pilgrim lab test<script>window.close()</script></body></html>`
2. Double-click it (it opens and closes), which gives 111001.
3. Save `WScript.Echo("Pilgrim lab test");` as `Downloads\invoice.js` and double-click it, which gives 111002.
4. 111003 needs Office: if it is installed, run Atomic Red Team T1204.002 on the lab VM; otherwise show regression case UC10-03.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Only user-download locations count: IT logon scripts run from `\\server\netlogon` or Program Files.
- Office starting a shell is rare in this organisation, so it is always worth a look.
- Negative cases UC10-04/05 prove that an admin script from a protected folder stays quiet.

## Regression cases

5 cases (3 positive, 2 negative) in [`tests/cases/uc10.json`](../../tests/cases/uc10.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC10-01 | positive | mshta opens an HTA from Downloads -> 111001 |
| UC10-02 | positive | wscript runs a .js extracted from a zipped invoice in Temp -> 111002 |
| UC10-03 | positive | Word starts PowerShell -> 111003 |
| UC10-04 | negative | IT logon script from the netlogon share (no alert) |
| UC10-05 | negative | Vendor help file opened with mshta from Program Files (no alert) |

## How to improve it

- Add Sysmon event 11 for files dropped by Outlook into `Content.Outlook` and correlate the drop with the execution.
- Active response: kill the process tree and isolate the host with a firewall rule.
- Send the attachment hash to the VirusTotal integration that is already configured on the manager.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
