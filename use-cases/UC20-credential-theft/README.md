[All use cases](../../README.md#the-use-cases) · Previous: [UC19](../UC19-defense-evasion/README.md) · Next: [UC21](../UC21-discovery-burst/README.md)

# UC20: Credential theft from LSASS memory and registry hives

| | |
|---|---|
| **Tactic** | Credential Access |
| **ATT&CK** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) LSASS Memory, [T1003.002](https://attack.mitre.org/techniques/T1003/002/) Security Account Manager, [T1218.011](https://attack.mitre.org/techniques/T1218/011/) Rundll32 |
| **Runs on** | Windows 10 VM |
| **Top rule** | 112002 (level 14) |
| **Rules** | [`wazuh/rules/pp-200-uc20_credential_access_rules.xml`](../../wazuh/rules/pp-200-uc20_credential_access_rules.xml) |
| **Regression cases** | [`tests/cases/uc20.json`](../../tests/cases/uc20.json) |

## Why it matters

Stolen Windows credentials turn one infected staff PC into access to every system the staff member uses, including the booking back office and the document share. Dumping LSASS or the SAM hive is the standard way to get them.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Sysmon process access (event 10) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 112001 (12): a process opened lsass.exe with rights that allow reading its memory or duplicating its handles. The rule reads the access BITS (`PROCESS_VM_READ` 0x10, `PROCESS_DUP_HANDLE` 0x40) instead of a few fixed masks, so 0x1410, 0x1438, 0x1fffff are caught; Wazuh's 92900 only knows 0x1010 and 0x40.
- 112002 (14): ...and the call stack shows a dump routine (dbghelp/dbgcore `MiniDumpWriteDump`, comsvcs.dll) or code with no backing module.
- 112003 (14): rundll32 calling comsvcs.dll MiniDump. 112004 (14): reg.exe saving or exporting the SAM, SECURITY or SYSTEM hive (Wazuh's 92026 only knows SAM).

### Rules (4 alerting, 1 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 112001 | 12 | UC20 LSASS memory opened for reading on `$(win.system.computer)` by `$(win.eventdata.sourceImage)` (access `$(win.eventdata.grantedAccess)`) | T1003.001 |
| 112002 | 14 | UC20 LSASS memory being dumped on `$(win.system.computer)` by `$(win.eventdata.sourceImage)` (dump routine in call stack) | T1003.001 |
| 112003 | 14 | UC20 comsvcs.dll MiniDump called through rundll32 on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1003.001, T1218.011 |
| 112004 | 14 | UC20 Credential hive copied with reg.exe on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1003.002 |
| 112009 | 0 (silent) | UC20 tuning: Microsoft Defender scanning LSASS (silences Wazuh 92900 for Defender itself) |  |

<details>
<summary>Rule XML</summary>

```xml
<rule id="112001" level="12">
  <if_sid>92900, 61612</if_sid>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe$</field>
  <field name="win.eventdata.grantedAccess" type="pcre2">(?i)^0x[0-9a-f]*[13-79b-f][0-9a-f]$</field>
  <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)\\Windows\\+System32\\+(csrss|wininit|services|lsm|svchost|wbem\\+WmiPrvSE)\.exe$|\\Program Files( \(x86\))?\\+|\\ProgramData\\+Microsoft\\+Windows Defender\\+Platform\\+</field>
  <description>UC20 LSASS memory opened for reading on $(win.system.computer) by $(win.eventdata.sourceImage) (access $(win.eventdata.grantedAccess))</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>pp_credential_access,pp_lsass_read,</group>
</rule>

<rule id="112002" level="14">
  <if_group>pp_lsass_read</if_group>
  <field name="win.eventdata.callTrace" type="pcre2">(?i)dbghelp\.dll|dbgcore\.dll|comsvcs\.dll|UNKNOWN\(</field>
  <description>UC20 LSASS memory being dumped on $(win.system.computer) by $(win.eventdata.sourceImage) (dump routine in call stack)</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>pp_credential_access,</group>
</rule>

<rule id="112003" level="14">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^rundll32\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)comsvcs(\.dll)?(?:\\?")?\s*[, ]\s*(#\+?24\b|minidump)</field>
  <description>UC20 comsvcs.dll MiniDump called through rundll32 on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1003.001</id>
    <id>T1218.011</id>
  </mitre>
  <group>pp_credential_access,</group>
</rule>

<rule id="112004" level="14">
  <if_sid>92026, 92025, 61603, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^reg\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\b(save|export)\s+"?(HKLM|HKEY_LOCAL_MACHINE)\\+(SAM|SECURITY|SYSTEM)"?(\s|$)</field>
  <description>UC20 Credential hive copied with reg.exe on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1003.002</id>
  </mitre>
  <group>pp_credential_access,</group>
</rule>

<!-- Tuning, found live in the lab: Defender scans LSASS (for example when a USB stick is plugged in) and
     Wazuh's 92900 raised it at level 12. Level 0 here silences only Defender's own platform binary. -->
<rule id="112009" level="0">
  <if_sid>92900</if_sid>
  <field name="win.eventdata.sourceImage" type="pcre2">(?i)^C:\\+ProgramData\\+Microsoft\\+Windows Defender\\+Platform\\+[^\\]+\\+MsMpEng\.exe$</field>
  <description>UC20 tuning: Microsoft Defender scanning LSASS (silences Wazuh 92900 for Defender itself)</description>
  <group>pp_tuning,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**112001, level 12:** UC20 LSASS memory opened for reading on WIN10-LAB by C:\\Users\\Public\\tool.exe (access 0x1010)

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "10"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:00:00.000", "sourceProcessGUID": "{11111111-2222-3333-4444-555555555556}", "sourceProcessId": "5120", "sourceThreadId": "5124", "sourceImage": "C:\\\\Users\\\\Public\\\\tool.exe", "targetProcessGUID": "{11111111-2222-3333-4444-555555555557}", "targetProcessId": "712", "targetImage": "C:\\\\Windows\\\\system32\\\\lsass.exe", "grantedAccess": "0x1010", "callTrace": "C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll+9d4c4|C:\\\\Windows\\\\System32\\\\KERNELBASE.dll+2c13e", "sourceUser": "WIN10-LAB\\\\ahmed", "targetUser": "NT AUTHORITY\\\\SYSTEM"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM (elevated): `reg save HKLM\SYSTEM Q:\sys.hiv` with a drive letter that does not exist (Q:). The command fails, nothing is written, and 112004 fires on the command line.
2. LSASS rules: run Atomic Red Team T1003.001 on the lab VM (pick one test). Defender may block it, which also produces Defender alert 62123 next to UC20.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Windows and security processes that legitimately read LSASS (csrss, wininit, services, lsm, svchost, WMI, Program Files, the Defender platform folder) are excluded by path (case UC20-07).
- Query-only access (0x1000) does not match (case UC20-08); exporting a single key under HKLM\SYSTEM does not match (UC20-09).

## Regression cases

10 cases (6 positive, 4 negative) in [`tests/cases/uc20.json`](../../tests/cases/uc20.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC20-01 | positive | Unknown tool opens LSASS with 0x1010 (Wazuh 92900 path) -> 112001 |
| UC20-02 | positive | Full access 0x1fffff that Wazuh 92900 does not list -> 112001 |
| UC20-03 | positive | Task Manager dump: MiniDumpWriteDump in the call stack -> 112002 |
| UC20-04 | positive | rundll32 comsvcs.dll MiniDump -> 112003 |
| UC20-05 | positive | reg save of the SAM hive (Wazuh 92026 path) -> 112004 |
| UC20-06 | positive | reg save of the SYSTEM hive (gap in Wazuh 92026) -> 112004 |
| UC20-07 | negative | Defender scanning LSASS (allow-listed path, no alert) |
| UC20-08 | negative | Query-only access 0x1000 (no alert) |
| UC20-09 | negative | Exporting one service key under HKLM\SYSTEM (no alert) |
| UC20-10 | negative | Found live: Defender opens LSASS with 0x1010 - Wazuh's 92900 silenced by tuning rule 112009 |

## How to improve it

- Turn on LSA protection (RunAsPPL) and Credential Guard, and alert if they are switched off.
- Correlate 112001 with a new admin logon from the same host (pass-the-hash follow-up).

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
