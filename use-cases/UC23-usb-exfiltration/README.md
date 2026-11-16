[All use cases](../../README.md#the-use-cases) · Previous: [UC22](../UC22-remote-execution/README.md) · Next: [UC24](../UC24-dns-tunnelling/README.md)

# UC23: Pilgrim documents copied to a USB drive

| | |
|---|---|
| **Tactic** | Exfiltration |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) Exfiltration over USB |
| **Runs on** | Windows 10 VM |
| **Top rule** | 112305 (level 14) |
| **Rules** | [`wazuh/rules/pp-230-uc23_usb_exfiltration_rules.xml`](../../wazuh/rules/pp-230-uc23_usb_exfiltration_rules.xml) |
| **Regression cases** | [`tests/cases/uc23.json`](../../tests/cases/uc23.json) |

## Why it matters

Passport scans and visa batches are what makes a pilgrim agency worth robbing, and a USB stick is the simplest way out of the building: no network, no proxy, no email gateway.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| Windows Security log, new external device (6416) | `Security` channel, collected by the agent's default config; audit policy set by `windows/setup-windows.ps1` | Built-in `windows_eventchannel` |
| Sysmon file created (event 11) | `Microsoft-Windows-Sysmon/Operational` on the Windows 10 VM (config `windows/pilgrim-sysmon.xml`) | Built-in `windows_eventchannel` |

## Detection logic

- 112301 (8): a USB storage device (class DiskDrive) was connected (needs 'Audit PNP Activity').
- 112302 (2, silent): a file was written to a drive other than C:. Sysmon logs these because `pilgrim-sysmon.xml` includes every file created outside C:.
- 112303 (12): 10 or more files written to an external drive by the same process within 2 minutes.
- 112304 (13): ...and they are pilgrim identity documents (passport, visa, national ID, manifest, spreadsheets).
- 112305 (14): ...to a drive plugged in during the last 30 minutes.
- The burst counts 112302 by ID (`if_matched_sid`) and is attached with `if_group`, so every file is counted once.

### Rules (4 alerting, 1 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 112301 | 8 | UC23 USB storage device connected to `$(win.system.computer)`: `$(win.eventdata.deviceDescription)` | T1052.001 |
| 112302 | 2 (silent) | UC23 File written to an external drive (classification): `$(win.eventdata.targetFilename)` | T1052.001 |
| 112303 | 12 | UC23 Bulk copy to an external drive on `$(win.system.computer)`: 10+ files in 2 minutes by `$(win.eventdata.image)`, last `$(win.eventdata.targetFilename)` | T1052.001 |
| 112304 | 13 | UC23 Pilgrim identity documents bulk-copied to an external drive on `$(win.system.computer)`: `$(win.eventdata.targetFilename)` | T1052.001 |
| 112305 | 14 | UC23 Pilgrim identity documents copied to a USB drive plugged in during the last 30 minutes on `$(win.system.computer)` | T1052.001 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="112301" level="8">
  <if_sid>60227</if_sid>
  <field name="win.eventdata.className" type="pcre2">(?i)^DiskDrive$</field>
  <description>UC23 USB storage device connected to $(win.system.computer): $(win.eventdata.deviceDescription)</description>
  <mitre>
    <id>T1052.001</id>
  </mitre>
  <group>pp_usb,</group>
</rule>

<rule id="112302" level="2">
  <if_sid>61613, 92216</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)^[d-z]:\\</field>
  <description>UC23 File written to an external drive (classification): $(win.eventdata.targetFilename)</description>
  <mitre>
    <id>T1052.001</id>
  </mitre>
  <group>pp_usb_write,</group>
</rule>

<rule id="112303" level="12" frequency="10" timeframe="120" ignore="300">
  <if_group>pp_usb_write</if_group>
  <if_matched_sid>112302</if_matched_sid>
  <same_field>win.eventdata.image</same_field>
  <description>UC23 Bulk copy to an external drive on $(win.system.computer): 10+ files in 2 minutes by $(win.eventdata.image), last $(win.eventdata.targetFilename)</description>
  <mitre>
    <id>T1052.001</id>
  </mitre>
  <group>pp_usb_bulk,</group>
</rule>

<rule id="112304" level="13">
  <if_group>pp_usb_bulk</if_group>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)passport|visa|iqama|national[_ -]?id|manifest|pilgrim|\.(csv|xlsx?)$</field>
  <description>UC23 Pilgrim identity documents bulk-copied to an external drive on $(win.system.computer): $(win.eventdata.targetFilename)</description>
  <mitre>
    <id>T1052.001</id>
  </mitre>
  <group>pp_usb_identity_docs,</group>
</rule>

<rule id="112305" level="14" timeframe="1800">
  <if_group>pp_usb_identity_docs</if_group>
  <if_matched_sid>112301</if_matched_sid>
  <description>UC23 Pilgrim identity documents copied to a USB drive plugged in during the last 30 minutes on $(win.system.computer)</description>
  <mitre>
    <id>T1052.001</id>
  </mitre>
  <group>pp_usb_fresh_drive,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**112303, level 12:** UC23 Bulk copy to an external drive on WIN10-LAB: 10+ files in 2 minutes by C:\\Windows\\explorer.exe, last E:\\Trip\\IMG_0010.jpg

```
{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "channel": "Microsoft-Windows-Sysmon/Operational", "level": "4", "computer": "WIN10-LAB", "eventID": "11"}, "eventdata": {"ruleName": "-", "utcTime": "2026-11-11 10:05:00.000", "processGuid": "{11111111-2222-3333-4444-555555555559}", "processId": "3920", "image": "C:\\\\Windows\\\\explorer.exe", "targetFilename": "E:\\\\Trip\\\\IMG_0010.jpg", "creationUtcTime": "2026-11-11 10:05:00.000", "user": "WIN10-LAB\\\\ahmed"}}}
```

**112301, level 8:** UC23 USB storage device connected to WIN10-LAB: SanDisk Cruzer Blade USB Device

```
{"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "channel": "Security", "keywords": "0x8020000000000000", "computer": "WIN10-LAB", "eventID": "6416"}, "eventdata": {"subjectUserSid": "S-1-5-18", "subjectUserName": "WIN10-LAB$", "subjectDomainName": "WORKGROUP", "subjectLogonId": "0x3e7", "deviceId": "USBSTOR\\\\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\\\\4C530001231122", "deviceDescription": "SanDisk Cruzer Blade USB Device", "classId": "{4d36e967-e325-11ce-bfc1-08002be10318}", "className": "DiskDrive", "hardwareIds": "USBSTOR\\\\DiskSanDisk_Cruzer_Blade", "compatibleIds": "USBSTOR\\\\Disk", "locationInformation": "-"}}}
```

## How to test it live

Runs on: Windows 10 VM.

1. Plug the USB stick into the laptop. In VMware: **VM > Removable Devices >** your stick **> Connect (Disconnect from Host)**. It appears in the VM as a new drive (usually `E:`); if not, set **VM > Settings > USB Controller** to USB 3.1. This gives 112301.
2. In File Explorer open `C:\PilgrimShare`, right-click **PassportScans > Copy**, open the USB drive and paste. This gives 112305.
3. Clean up: delete the folder from the stick, then **VM > Removable Devices >** your stick **> Disconnect**.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- One-off copies stay silent; only bulk copies alert (case UC23-05).
- Holiday photos in bulk give the lower 112303, not the identity-document rules (case UC23-02).
- `ignore=300` keeps one large copy from producing a stream of alerts.

## Regression cases

5 cases (4 positive, 1 negative) in [`tests/cases/uc23.json`](../../tests/cases/uc23.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC23-01 | positive | USB stick connected -> 112301 |
| UC23-02 | positive | Ten holiday photos copied to E: -> 112303 (bulk, not identity documents) |
| UC23-03 | positive | Ten passport scans copied to E: -> 112304 |
| UC23-04 | positive | USB plugged in, then passport scans copied -> 112305 |
| UC23-05 | negative | Three files copied to USB (below threshold, silent) |

## How to improve it

- Block mass-storage devices by policy for staff who handle passports, and keep the rules as the safety net.
- Add the device serial number from 6416 to an approved-devices CDB list.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
