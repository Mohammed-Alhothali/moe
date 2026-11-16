[All use cases](../../README.md#the-use-cases) · Previous: [UC15](../UC15-privileged-groups/README.md) · Next: [UC17](../UC17-sudo-privilege-escalation/README.md)

# UC16: Expired seasonal staff account used

| | |
|---|---|
| **Tactic** | Initial Access / Persistence |
| **ATT&CK** | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Local Accounts |
| **Runs on** | Windows 10 VM |
| **Top rule** | 111601 (level 13) |
| **Rules** | [`wazuh/rules/pp-160-uc16_seasonal_account_rules.xml`](../../wazuh/rules/pp-160-uc16_seasonal_account_rules.xml) |
| **Regression cases** | [`tests/cases/uc16.json`](../../tests/cases/uc16.json) |

## Why it matters

Every Hajj season brings hundreds of temporary accounts for seasonal staff and guides. Accounts that outlive the season are a favourite way in, because nobody notices them being used.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Windows Security log, logon success / failure (4624, 4625) | `Security` channel, collected by the agent's default config; audit policy set by `windows/setup-windows.ps1` | Built-in `windows_eventchannel` |

- CDB list: [`wazuh/lists/pp-expired-seasonal`](../../wazuh/lists/pp-expired-seasonal)

## Detection logic

- When the season closes, HR exports the expired accounts into `etc/lists/pp-expired-seasonal`.
- 111601 (13): one of them logs on successfully. 111602 (10): someone tries and fails.
- 111601 attaches with `if_group authentication_success` plus event 4624, because logon events reach a copy of 60106 that an `if_sid` child is never attached to (verified in the engine).

### Rules (2 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111601 | 13 | UC16 Expired seasonal account `$(win.eventdata.targetUserName)` logged on to `$(win.system.computer)` (logon type `$(win.eventdata.logonType)`, from `$(win.eventdata.ipAddress)`). | T1078.003 |
| 111602 | 10 | UC16 Logon attempt with expired seasonal account `$(win.eventdata.targetUserName)` on `$(win.system.computer)` (from `$(win.eventdata.ipAddress)`). | T1078.003 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111601" level="13">
  <if_group>authentication_success</if_group>
  <field name="win.system.eventID">^4624$</field>
  <list field="win.eventdata.targetUserName" lookup="match_key">etc/lists/pp-expired-seasonal</list>
  <description>UC16 Expired seasonal account $(win.eventdata.targetUserName) logged on to $(win.system.computer) (logon type $(win.eventdata.logonType), from $(win.eventdata.ipAddress)).</description>
  <mitre>
    <id>T1078.003</id>
  </mitre>
  <group>pp_seasonal_account,</group>
</rule>

<rule id="111602" level="10">
  <if_sid>60122</if_sid>
  <list field="win.eventdata.targetUserName" lookup="match_key">etc/lists/pp-expired-seasonal</list>
  <description>UC16 Logon attempt with expired seasonal account $(win.eventdata.targetUserName) on $(win.system.computer) (from $(win.eventdata.ipAddress)).</description>
  <mitre>
    <id>T1078.003</id>
  </mitre>
  <group>pp_seasonal_account,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111601, level 13:** UC16 Expired seasonal account s1447.ops017 logged on to WIN10-LAB (logon type 2, from 192.168.56.1).

```
{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "channel": "Security", "keywords": "0x8020000000000000", "computer": "WIN10-LAB", "eventID": "4624"}, "eventdata": {"subjectUserSid": "S-1-5-18", "subjectUserName": "WIN10-LAB$", "targetUserName": "s1447.ops017", "targetDomainName": "WIN10-LAB", "logonType": "2", "ipAddress": "192.168.56.1", "workstationName": "WIN10-LAB", "logonProcessName": "User32", "authenticationPackageName": "Negotiate"}}}
```

**111602, level 10:** UC16 Logon attempt with expired seasonal account s1447.guide042 on WIN10-LAB (from 192.168.56.130).

```
{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "channel": "Security", "keywords": "0x8010000000000000", "computer": "WIN10-LAB", "eventID": "4625"}, "eventdata": {"subjectUserSid": "S-1-0-0", "targetUserName": "s1447.guide042", "targetDomainName": "WIN10-LAB", "status": "0xc000006d", "subStatus": "0xc000006a", "logonType": "3", "ipAddress": "192.168.56.130", "workstationName": "ATTACKER", "failureReason": "%%2313"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM (elevated): `net user s1447.ops017 Season#1447 /add` (a name on the list).
2. `runas /user:s1447.ops017 cmd` with the right password gives 111601; with a wrong one, 111602.
3. Clean up: `net user s1447.ops017 /delete`.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- The list holds exact usernames and is regenerated from HR data each season.
- Re-hired staff are removed from the list rather than excluded in the rule.

## Regression cases

3 cases (2 positive, 1 negative) in [`tests/cases/uc16.json`](../../tests/cases/uc16.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC16-01 | positive | Expired seasonal account logs on -> 111601 |
| UC16-02 | positive | Failed logon with an expired seasonal account -> 111602 |
| UC16-03 | negative | Normal staff logon (no alert) |

## How to improve it

- Disable expired accounts automatically from the same HR export, and keep the rule as the safety net.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
