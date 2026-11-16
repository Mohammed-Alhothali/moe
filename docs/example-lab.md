# The example lab

The detections are exercised in a small lab that plays a fictional Hajj and Umrah services provider,
*Rifadah Pilgrim Services*. The organisation, its users and its documents are invented. Paths below are relative
to the repository root.

## Machines

| Machine | Role | What it sends to Wazuh |
|---|---|---|
| Wazuh manager | SIEM (4.12) | - |
| web01 (Ubuntu, Wazuh agent) | Pilgrim portal: nginx, gunicorn, Flask | portal audit log, nginx access log, auditd, auth.log, FIM (web root, sudoers, cron) |
| Windows 10 (Wazuh agent + Sysmon) | Staff workstation and document share | Sysmon, Security, System, PowerShell and Defender logs; FIM on `C:\PilgrimShare` |
| Your laptop / phone | Users of the portal, SOC analyst | - |

## Setup

1. **web01** (copy this folder to the server):
   `sudo bash portal/deploy/setup.sh`
   This installs the portal at `http://<web01-ip>/`, seeds 2,300 synthetic pilgrims and loads the auditd rules.
2. **Wazuh manager** (copy this folder to the manager):
   `sudo bash wazuh/deploy_manager.sh`
   This first checks that none of the library's rule IDs already exists on the manager, then installs decoders,
   rules and lists, registers the lists, pushes the agent configuration to group `default`, validates everything
   with `wazuh-analysisd -t` and only then restarts. If validation fails it rolls back automatically.
3. **Windows 10 VM** (copy the `windows` folder; Sysmon must already be installed), in an elevated PowerShell:
   `powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1`
   This saves your current Sysmon configuration, applies `pilgrim-sysmon.xml`, turns on the audit categories and
   PowerShell script block logging the rules need, creates the synthetic `C:\PilgrimShare`, and restarts the agent.
4. **Prove the rules** on the manager:
   `sudo /var/ossec/framework/python/bin/python3 tests/run_on_manager.py`
   It replays every case made of log lines. Windows-event and FIM cases are listed as SKIP: `wazuh-logtest` cannot
   replay them, so they are proven live (and in `tests/lab-engine-report.md`).
5. **Dashboard branding:** on the Wazuh server, `cd branding && sudo bash apply-branding.sh`, then the two-minute
   App Settings step in `branding/README.md`.
6. **MOE SOC console:** on the Wazuh server, `cd console && sudo bash install-console.sh`, then open
   `https://<server>:8443`. It is a custom Wazuh front end: live attack path, overview, alert and log search,
   agents, ATT&CK coverage, the use-case library and triage (see `console/README.md`). For the Logs page, also run
   `sudo bash install-console.sh --enable-logs` once.
7. **Live tests:** each `use-cases/UCxx-*/README.md` has a "How to test it live" section, and
   [live-test-runbook.md](live-test-runbook.md) has all of them as short cards.

## Portal accounts (synthetic, created by the seed script)

| Account | Password | Role |
|---|---|---|
| pilgrim0001 ... pilgrim0300 | Pilgrim#2026 | pilgrim |
| agency.in01, .pk01, .id01, .eg01, .ng01, .sa01 | Agency#2026 | licensed agency |
| staff.ops01-03, staff.visa01, staff.reporting | Staff#2026 | operations staff |
| fin.approver01, fin.approver02 | Finance#2026 | finance approvers (staff role) |
| portal.admin | Admin#2026 | administrator |

These accounts exist only in the seeded lab database. Change the seed script before using the portal anywhere else.
