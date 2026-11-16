[All use cases](../../README.md#the-use-cases) · Previous: [UC14](../UC14-scheduled-tasks/README.md) · Next: [UC16](../UC16-expired-seasonal-accounts/README.md)

# UC15: Privileged group changes (backdoor administrator)

| | |
|---|---|
| **Tactic** | Persistence / Privilege Escalation |
| **ATT&CK** | [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation, [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Local Account |
| **Runs on** | Windows 10 VM |
| **Top rule** | 111503 (level 14) |
| **Rules** | [`wazuh/rules/pp-150-uc15_privileged_group_rules.xml`](../../wazuh/rules/pp-150-uc15_privileged_group_rules.xml) |
| **Regression cases** | [`tests/cases/uc15.json`](../../tests/cases/uc15.json) |

## Why it matters

Adding an account to Administrators or Remote Desktop Users is how an intruder keeps a way back in after the password of the first victim is reset. In a pilgrim agency only the identity team should ever do it.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Windows Security log, account created / member added (4720, 4732) | `Security` channel, collected by the agent's default config; audit policy set by `windows/setup-windows.ps1` | Built-in `windows_eventchannel` |

- CDB list: [`wazuh/lists/pp-identity-admins`](../../wazuh/lists/pp-identity-admins)

## Detection logic

- 111501 (13): a member is ADDED to Administrators by an account that is not on `etc/lists/pp-identity-admins`.
- 111502 (11): a member is added to Remote Desktop Users (refines Wazuh's 60179, which also fires on removals).
- 111503 (14): the same operator created an account and made it an administrator within 15 minutes.

### Rules (3 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111501 | 13 | UC15 Unapproved administrator grant on `$(win.system.computer)`: `$(win.eventdata.subjectUserName)` added `$(win.eventdata.memberSid)` to Administrators. | T1098 |
| 111502 | 11 | UC15 Remote access granted on `$(win.system.computer)`: `$(win.eventdata.subjectUserName)` added `$(win.eventdata.memberSid)` to Remote Desktop Users. | T1098 |
| 111503 | 14 | UC15 Backdoor account chain on `$(win.system.computer)`: `$(win.eventdata.subjectUserName)` created an account and made `$(win.eventdata.memberSid)` an administrator within 15 minutes. | T1136.001, T1098 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111501" level="13">
  <if_sid>60154</if_sid>
  <field name="win.system.eventID">^4732$</field>
  <list field="win.eventdata.subjectUserName" lookup="not_match_key">etc/lists/pp-identity-admins</list>
  <description>UC15 Unapproved administrator grant on $(win.system.computer): $(win.eventdata.subjectUserName) added $(win.eventdata.memberSid) to Administrators.</description>
  <mitre>
    <id>T1098</id>
  </mitre>
  <group>pp_privilege,</group>
</rule>

<rule id="111502" level="11">
  <if_sid>60179</if_sid>
  <field name="win.system.eventID">^4732$</field>
  <description>UC15 Remote access granted on $(win.system.computer): $(win.eventdata.subjectUserName) added $(win.eventdata.memberSid) to Remote Desktop Users.</description>
  <mitre>
    <id>T1098</id>
  </mitre>
  <group>pp_privilege,</group>
</rule>

<rule id="111503" level="14" timeframe="900">
  <if_sid>60154</if_sid>
  <field name="win.system.eventID">^4732$</field>
  <if_matched_sid>60109</if_matched_sid>
  <same_field>win.eventdata.subjectUserName</same_field>
  <description>UC15 Backdoor account chain on $(win.system.computer): $(win.eventdata.subjectUserName) created an account and made $(win.eventdata.memberSid) an administrator within 15 minutes.</description>
  <mitre>
    <id>T1136.001</id>
    <id>T1098</id>
  </mitre>
  <group>pp_privilege,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111501, level 13:** UC15 Unapproved administrator grant on WIN10-LAB: ahmed added S-1-5-21-1111111111-2222222222-3333333333-1009 to Administrators.

```
{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "channel": "Security", "keywords": "0x8020000000000000", "computer": "WIN10-LAB", "eventID": "4732"}, "eventdata": {"subjectUserName": "ahmed", "subjectDomainName": "WIN10-LAB", "memberName": "-", "memberSid": "S-1-5-21-1111111111-2222222222-3333333333-1009", "targetUserName": "Administrators", "targetDomainName": "Builtin", "targetSid": "S-1-5-32-544"}}}
```

**111502, level 11:** UC15 Remote access granted on WIN10-LAB: ahmed added S-1-5-21-1111111111-2222222222-3333333333-1009 to Remote Desktop Users.

```
{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "channel": "Security", "keywords": "0x8020000000000000", "computer": "WIN10-LAB", "eventID": "4732"}, "eventdata": {"subjectUserName": "ahmed", "subjectDomainName": "WIN10-LAB", "memberName": "-", "memberSid": "S-1-5-21-1111111111-2222222222-3333333333-1009", "targetUserName": "Remote Desktop Users", "targetDomainName": "Builtin", "targetSid": "S-1-5-32-555"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM (elevated): `net user pplab01 Lab#2026x /add` then `net localgroup administrators pplab01 /add` gives 111503.
2. Clean up: `net user pplab01 /delete`.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Approved identity administrators are a CDB list owned by the identity team; their routine changes stay at Wazuh's level.
- 111503 needs both halves of the chain from the same operator.

## Regression cases

4 cases (3 positive, 1 negative) in [`tests/cases/uc15.json`](../../tests/cases/uc15.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC15-01 | positive | Non-approved operator adds a member to Administrators -> 111501 |
| UC15-02 | negative | Approved identity admin adds a member (stays at Wazuh default 60154) |
| UC15-03 | positive | Member added to Remote Desktop Users -> 111502 |
| UC15-04 | positive | Account created then made admin by the same operator -> 111503 |

## How to improve it

- Active response: disable the new account automatically when 111503 fires.
- Add the domain groups (4728/4756) when the agency moves to Active Directory.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
