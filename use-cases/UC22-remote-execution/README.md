[All use cases](../../README.md#the-use-cases) · Previous: [UC21](../UC21-discovery-burst/README.md) · Next: [UC23](../UC23-usb-exfiltration/README.md)

# UC22: Lateral movement through remote services (PsExec and look-alikes)

| | |
|---|---|
| **Tactic** | Lateral Movement |
| **ATT&CK** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) SMB/Windows Admin Shares, [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Windows Service, [T1569.002](https://attack.mitre.org/techniques/T1569/002/) Service Execution |
| **Runs on** | Windows 10 VM |
| **Top rule** | 112205 (level 14) |
| **Rules** | [`wazuh/rules/pp-220-uc22_remote_execution_rules.xml`](../../wazuh/rules/pp-220-uc22_remote_execution_rules.xml) |
| **Regression cases** | [`tests/cases/uc22.json`](../../tests/cases/uc22.json) |

## Why it matters

Ransomware crews spread from the first PC to the file and booking servers by installing a remote service, PsExec style. Catching the first remote service install stops the spread before the share is encrypted.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Windows System log, service installed (7045) | `System` channel, collected by the agent's default config | Built-in `windows_eventchannel` |
| Sysmon named pipe (event 17/18) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 112201 (12): a service whose binary or command is a remote-execution tool (PSEXESVC, RemCom, PAExec, csexec, winexesvc) or a shell one-liner (`%COMSPEC%`, `cmd /c`, powershell), the pattern of Impacket-style tools.
- 112202 (10): any new service whose binary lives in a user-writable folder.
- 112203 (12): a named pipe used by those tools. 112204 (10): a process started by a remote-execution service.
- 112205 (14): a 112201 install followed within 2 minutes by its pipe or child process on the same host.

### Rules (5 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 112201 | 12 | UC22 Remote-execution service installed on `$(win.system.computer)`: `$(win.eventdata.serviceName)` -> `$(win.eventdata.imagePath)` | T1569.002, T1021.002 |
| 112202 | 10 | UC22 Service installed from a user-writable folder on `$(win.system.computer)`: `$(win.eventdata.serviceName)` -> `$(win.eventdata.imagePath)` | T1543.003 |
| 112203 | 12 | UC22 Remote-execution named pipe on `$(win.system.computer)`: `$(win.eventdata.pipeName)` (`$(win.eventdata.image)`) | T1021.002 |
| 112204 | 10 | UC22 Command run through a remote-execution service on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1569.002 |
| 112205 | 14 | UC22 Remote execution confirmed on `$(win.system.computer)`: a remote-execution service was installed and is now running commands | T1021.002, T1569.002 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="112201" level="12">
  <if_sid>61100, 61138</if_sid>
  <field name="win.system.eventID">^7045$</field>
  <field name="win.eventdata.imagePath" type="pcre2">(?i)PSEXESVC|RemCom|PAExec|csexec|winexesvc|%COMSPEC%|\bcmd(\.exe)?(?:\\?")?\s+/[ckq]\b|\bpowershell(\.exe)?\b|\\\\+127\.0\.0\.1\\+|\\+ADMIN\$\\+</field>
  <description>UC22 Remote-execution service installed on $(win.system.computer): $(win.eventdata.serviceName) -> $(win.eventdata.imagePath)</description>
  <mitre>
    <id>T1569.002</id>
    <id>T1021.002</id>
  </mitre>
  <group>pp_lateral,</group>
</rule>

<rule id="112202" level="10">
  <if_sid>61100, 61138</if_sid>
  <field name="win.system.eventID">^7045$</field>
  <field name="win.eventdata.imagePath" type="pcre2">(?i)^(?!.*\\+ProgramData\\+Microsoft\\+Windows Defender\\+).*\\+(Users|Windows\\+Temp|Temp|AppData|PerfLogs|ProgramData)\\+</field>
  <description>UC22 Service installed from a user-writable folder on $(win.system.computer): $(win.eventdata.serviceName) -> $(win.eventdata.imagePath)</description>
  <mitre>
    <id>T1543.003</id>
  </mitre>
  <group>pp_lateral,</group>
</rule>

<rule id="112203" level="12">
  <if_sid>61645, 61646</if_sid>
  <field name="win.eventdata.pipeName" type="pcre2">(?i)^\\+(PSEXESVC|RemCom_|paexec|csexec|winexesvc)</field>
  <description>UC22 Remote-execution named pipe on $(win.system.computer): $(win.eventdata.pipeName) ($(win.eventdata.image))</description>
  <mitre>
    <id>T1021.002</id>
  </mitre>
  <group>pp_lateral,pp_remote_exec_activity,</group>
</rule>

<rule id="112204" level="10">
  <if_sid>92068, 61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(PSEXESVC|RemComSvc|PAExec[^\\]*|csexecsvc|winexesvc)\.exe$</field>
  <description>UC22 Command run through a remote-execution service on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1569.002</id>
  </mitre>
  <group>pp_lateral,pp_remote_exec_activity,</group>
</rule>

<rule id="112205" level="14" timeframe="120" ignore="120">
  <if_group>pp_remote_exec_activity</if_group>
  <if_matched_sid>112201</if_matched_sid>
  <description>UC22 Remote execution confirmed on $(win.system.computer): a remote-execution service was installed and is now running commands</description>
  <mitre>
    <id>T1021.002</id>
    <id>T1569.002</id>
  </mitre>
  <group>pp_lateral,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**112201, level 12:** UC22 Remote-execution service installed on WIN10-LAB: PSEXESVC -> %SystemRoot%\\PSEXESVC.exe

```
{"win": {"system": {"providerName": "Service Control Manager", "providerGuid": "{555908d1-a6d7-4695-8e1e-26931d2012f4}", "channel": "System", "level": "4", "keywords": "0x8080000000000000", "computer": "WIN10-LAB", "eventID": "7045"}, "eventdata": {"serviceName": "PSEXESVC", "imagePath": "%SystemRoot%\\\\PSEXESVC.exe", "serviceType": "user mode service", "startType": "demand start", "accountName": "LocalSystem"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM (elevated): `sc.exe create PPLab binPath= "cmd.exe /c echo pilgrim-lab"` gives 112201 (the service never starts properly; the install is what is detected).
2. Clean up: `sc.exe delete PPLab`.
3. Optional: with Sysinternals PsExec, `PsExec64.exe -accepteula -s cmd /c whoami` gives 112201, 112203, 112204 and 112205.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Normal software installing a service under Program Files stays at Wazuh's 61138 (case UC22-07).
- The Defender platform folder is excluded from the user-writable rule (case UC22-08).
- IT staff who use PsExec on purpose can be tuned by host or account after the first review.

## Regression cases

8 cases (6 positive, 2 negative) in [`tests/cases/uc22.json`](../../tests/cases/uc22.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC22-01 | positive | PsExec service installed -> 112201 |
| UC22-02 | positive | smbexec-style service running a cmd one-liner -> 112201 |
| UC22-03 | positive | Service binary in C:\Users\Public -> 112202 |
| UC22-04 | positive | PSEXESVC named pipe -> 112203 |
| UC22-05 | positive | Command started by PSEXESVC -> 112204 |
| UC22-06 | positive | Service install, then its pipe -> 112205 |
| UC22-07 | negative | Normal software installs a service under Program Files (no UC22 alert) |
| UC22-08 | negative | Defender platform update re-registers its service (no UC22 alert) |

## How to improve it

- Correlate with a network logon (4624 type 3) from another internal host just before the install.
- Block service creation over SMB from workstations with a firewall rule; keep the rule as detection.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
