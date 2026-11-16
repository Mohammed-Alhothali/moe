[All use cases](../../README.md#the-use-cases) · Previous: [UC24](../UC24-dns-tunnelling/README.md)

# UC25: Ransomware behaviour against the pilgrim document share

| | |
|---|---|
| **Tactic** | Impact |
| **ATT&CK** | [T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction, [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact, [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery |
| **Runs on** | Windows 10 VM |
| **Top rule** | 112506 (level 15) |
| **Rules** | [`wazuh/rules/pp-250-uc25_ransomware_rules.xml`](../../wazuh/rules/pp-250-uc25_ransomware_rules.xml) |
| **Regression cases** | [`tests/cases/uc25.json`](../../tests/cases/uc25.json) |

## Why it matters

Passport scans and visa documents for the season live on this share. If they are encrypted in the weeks before departure, pilgrims miss their visa windows; the agency cannot just restore next week.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| File integrity monitoring (Windows) | syscheck realtime on `C:\PilgrimShare` (shared `agent.conf`) | Built-in syscheck |
| Sysmon process creation (event 1) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 112501 (2, silent): a file in `C:\PilgrimShare` was added, changed or deleted.
- 112502 (13): 20 or more changes within 60 seconds. 112503 (12): a ransom-note style file appeared.
- 112504 (14): the burst is renaming documents to a second extension (`passport.pdf.locked`).
- 112505 (14): a command that destroys recovery options (vssadmin delete shadows / resize shadowstorage, wmic shadowcopy delete, wbadmin delete, bcdedit recoveryenabled no, PowerShell Win32_ShadowCopy deletion).
- 112506 (15): mass change on the share on a host that destroyed recovery options in the last 30 minutes. It joins a Sysmon event with a FIM event; Wazuh correlates per agent, so no shared field is needed.

### Rules (5 alerting, 1 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 112501 | 2 (silent) | UC25 Change on the pilgrim document share (classification): `$(file)` | T1486 |
| 112502 | 13 | UC25 Mass file changes on the pilgrim document share: 20+ in 60 seconds, last `$(file)` | T1486, T1485 |
| 112503 | 12 | UC25 Ransom-note style file created on the pilgrim document share: `$(file)` | T1486 |
| 112504 | 14 | UC25 Documents on the pilgrim share are being renamed with an extra extension (encryption pattern): `$(file)` | T1486 |
| 112505 | 14 | UC25 Recovery options being destroyed on `$(win.system.computer)`: `$(win.eventdata.commandLine)` | T1490 |
| 112506 | 15 | UC25 Ransomware attack in progress: mass changes on the pilgrim share after recovery options were destroyed on the same host | T1486, T1490 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="112501" level="2">
  <if_sid>550, 553, 554</if_sid>
  <field name="file" type="pcre2">(?i)^c:\\+pilgrimshare\\+</field>
  <description>UC25 Change on the pilgrim document share (classification): $(file)</description>
  <mitre>
    <id>T1486</id>
  </mitre>
  <group>pp_share_change,</group>
</rule>

<rule id="112502" level="13" frequency="20" timeframe="60" ignore="300">
  <if_group>pp_share_change</if_group>
  <if_matched_sid>112501</if_matched_sid>
  <description>UC25 Mass file changes on the pilgrim document share: 20+ in 60 seconds, last $(file)</description>
  <mitre>
    <id>T1486</id>
    <id>T1485</id>
  </mitre>
  <group>pp_share_burst,pp_ransom_stage,</group>
</rule>

<rule id="112503" level="12">
  <if_sid>554</if_sid>
  <field name="file" type="pcre2">(?i)^c:\\+pilgrimshare\\+(.*\\+)?[^\\]*(readme|decrypt|restore|recover|how[_ -]?to|ransom|unlock)[^\\]*\.(txt|html?|hta|url)$</field>
  <description>UC25 Ransom-note style file created on the pilgrim document share: $(file)</description>
  <mitre>
    <id>T1486</id>
  </mitre>
  <group>pp_ransom_note,</group>
</rule>

<rule id="112504" level="14">
  <if_group>pp_share_burst</if_group>
  <field name="file" type="pcre2">(?i)\.(pdf|jpe?g|png|tiff?|docx?|xlsx?|csv|txt)\.[a-z0-9]{2,12}$</field>
  <description>UC25 Documents on the pilgrim share are being renamed with an extra extension (encryption pattern): $(file)</description>
  <mitre>
    <id>T1486</id>
  </mitre>
  <group>pp_share_encrypt,pp_ransom_stage,</group>
</rule>

<rule id="112505" level="14">
  <if_sid>61603, 92025, 92028, 92042, 92069</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\bvssadmin(\.exe)?(?:\\?")?\s+(delete\s+shadows|resize\s+shadowstorage)\b|\bwmic(\.exe)?(?:\\?")?\s+.*\bshadowcopy\b.*\bdelete\b|\bwbadmin(\.exe)?(?:\\?")?\s+delete\s+(catalog|systemstatebackup|backup)\b|\bbcdedit(\.exe)?(?:\\?")?\s+.*\b(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)\b|Win32_ShadowCopy\b.*\b(Delete\(\)|Remove-(WmiObject|CimInstance))|\b(Get-WmiObject|gwmi|Get-CimInstance)\b.*Win32_ShadowCopy\b.*\|\s*(Remove-|%\s*\{\s*\$_\.Delete)</field>
  <description>UC25 Recovery options being destroyed on $(win.system.computer): $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1490</id>
  </mitre>
  <group>pp_recovery_inhibit,</group>
</rule>

<rule id="112506" level="15" timeframe="1800">
  <if_group>pp_ransom_stage</if_group>
  <if_matched_sid>112505</if_matched_sid>
  <description>UC25 Ransomware attack in progress: mass changes on the pilgrim share after recovery options were destroyed on the same host</description>
  <mitre>
    <id>T1486</id>
    <id>T1490</id>
  </mitre>
  <group>pp_ransomware,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**112502, level 13:** UC25 Mass file changes on the pilgrim document share: 20+ in 60 seconds, last c:\pilgrimshare\passportscans\passport_0020.pdf

```
File 'c:\pilgrimshare\passportscans\passport_0020.pdf' deleted
```

**112503, level 12:** UC25 Ransom-note style file created on the pilgrim document share: c:\pilgrimshare\passportscans\README_RESTORE_FILES.txt

```
File 'c:\pilgrimshare\passportscans\README_RESTORE_FILES.txt' added
```

## How to test it live

Runs on: Windows 10 VM.

1. On the Windows VM (elevated): `vssadmin delete shadows /for=Q: /quiet` with a drive letter that does not exist. It fails harmlessly and gives 112505.
2. In Explorer, select the 40 synthetic files in `C:\PilgrimShare\PassportScans` and delete them. The 20th deletion gives 112506 (level 15), or 112502 if you skipped the first step.
3. In Notepad, save an empty `README_RESTORE_FILES.txt` in `C:\PilgrimShare`, which gives 112503.
4. Put the files back with `powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1 -SeedShareOnly` (this itself looks like a mass change, which is expected).

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Single-file edits are silent; only bursts alert (case UC25-09).
- 112504 needs a document extension followed by another one, so normal saves never match.
- Listing shadow copies does not alert (case UC25-08).

## Regression cases

10 cases (8 positive, 2 negative) in [`tests/cases/uc25.json`](../../tests/cases/uc25.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC25-01 | positive | 20 files deleted from the share in a minute -> 112502 |
| UC25-02 | positive | Ransom note written to the share -> 112503 |
| UC25-03 | positive | Documents renamed to .pdf.locked -> 112504 |
| UC25-04 | positive | vssadmin delete shadows -> 112505 |
| UC25-05 | positive | wmic shadowcopy delete -> 112505 |
| UC25-06 | positive | bcdedit disables recovery -> 112505 |
| UC25-07 | positive | Shadow copies deleted, then mass encryption of the share -> 112506 |
| UC25-08 | negative | Listing shadow copies (no alert) |
| UC25-09 | negative | Five documents edited by staff (below threshold, silent) |
| UC25-11 | positive | Found live: vssadmin typed in PowerShell (quoted program path) -> 112505 |

## How to improve it

- Active response: disable the SMB session or isolate the host when 112504 or 112506 fires.
- Add canary files with names that sort first (`!!!_canary.docx`) and alert on any change to them.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
