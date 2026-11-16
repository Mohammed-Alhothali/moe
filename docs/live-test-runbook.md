# Live-test runbook

One card per use case: where to run it, what to do step by step, which search shows the alert, and the three points that explain the detection.
Windows commands assume you are in the folder that holds this repository's `windows` files. Do UC23 before UC25 (UC25 deletes the files UC23 copies) and restore the share after UC25 with `.\setup-windows.ps1 -SeedShareOnly`.
Full pages (logic, tuning, regression cases) are in `use-cases/UCxx-*/README.md`.

## Before you start (10 minutes)

1. Wazuh dashboard > **Agents**: web01 and the Windows VM are both **Active**.
2. Clocks agree (correlation windows depend on it): `timedatectl` on Linux, `w32tm /query /status` on Windows.
3. The portal opens at `http://<web01-ip>/` from the laptop.
4. Windows VM: `Get-Service Sysmon64` is Running; the share is full: `powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1 -SeedShareOnly`.
5. web01: `ls -l /var/log/auth.log` exists (UC17). If not: `sudo apt install rsyslog`.
6. Open **Threat Hunting > Events** and keep the time picker on *Last 15 minutes*. Filter each demo with `rule.id:<id>`; every library alert description starts with its use case (`UC07 ...`).
7. Open the **MOE SOC console** at `https://<wazuh-server>:8443` next to it, on the **Live** page. Before each test click **Start a fresh window**: you then see only the use case you run light up on the attack path. Clicking a use case shows these same steps; clicking an alert shows its fields, the original event and the rule XML. The console's **Alerts** page accepts the same `rule.id:<id>` searches as Threat Hunting.

## If an alert does not appear

1. Is the source event there? Event Viewer (Sysmon / Security / System / Defender) on Windows; the log file on web01.
2. Did the manager receive it? `sudo grep -c '<rule id>' /var/ossec/logs/alerts/alerts.json` or `sudo tail -f /var/ossec/logs/alerts/alerts.json`.
3. Agent side: `C:\Program Files (x86)\ossec-agent\ossec.log` or `/var/ossec/logs/ossec.log` for errors.
4. Burst rules count events per agent within a window: repeat the whole step quickly rather than one event at a time.

## UC01 - Automated booking abuse (slot scalping bots)

**Where:** Laptop browser (portal)  |  **ATT&CK:** T1499.003 Application Exhaustion Flood  |  **Strongest alert:** 110102 (level 12)

1. Sign in as `pilgrim0042` / `Pilgrim#2026` and open **Bookings**.
2. Click **Book** on 10 different slots within a minute (results like *full* or *duplicate* still count).
3. In Wazuh, filter `rule.id:110101`. The alert names the account and source IP.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110101`.

**Key points:**
- *Why here:* Arrival slots sell out in minutes; bots grab them for resale, so real pilgrims lose their place.
- *Logic:* Silent base rule counts booking attempts; 10 per account per minute, or 15 per IP across rotating accounts, alerts.
- *False positives:* Shared hotel and carrier NAT gets a higher per-IP threshold; load-test IPs are a CDB list; ignore=120 stops alert storms.
- *Next improvement:* Active response to block the IP for 10 minutes on the bot-farm rule.

## UC02 - Credential stuffing and password guessing

**Where:** Laptop browser (portal)  |  **ATT&CK:** T1110.004 Credential Stuffing, T1110.001 Password Guessing  |  **Strongest alert:** 110202 (level 11)

1. Sign out. On **Sign in**, enter 5 made-up usernames with any password, which gives 110202.
2. Enter wrong passwords for `pilgrim0001` to `pilgrim0008`, which gives 110201.
3. Enter a wrong password for `agency.in01` 6 times, which gives 110203.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110201 or rule.id:110202 or rule.id:110203`.

**Key points:**
- *Why here:* One stolen agency login exposes thousands of pilgrims' passports and bookings.
- *Logic:* Failures are split by reason; non-existent usernames from one IP (110202) is the high-confidence stuffing signal.
- *False positives:* Hotel NAT mistypes stay below thresholds; the scanner is allowlisted; duplicate nginx 401 alerts are absorbed by a no_log tuning rule.
- *Next improvement:* Enrich the source IP with a threat-intel CDB list of proxy and botnet ranges.

## UC03 - Account takeover after a credential attack

**Where:** Laptop browser (portal)  |  **ATT&CK:** T1110 Brute Force then T1078 Valid Accounts  |  **Strongest alert:** 110302 (level 13)

1. From your laptop, trigger 110202 (5 made-up usernames, see UC02).
2. Then sign in correctly as `pilgrim0007` / `Pilgrim#2026` from the same laptop, which gives 110301.
3. Or: 6 wrong passwords for `agency.in01`, then the right one (`Agency#2026`), which gives 110302.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110202 or rule.id:110301 or rule.id:110302`.

**Key points:**
- *Why here:* A failed attack is noise; a failed attack followed by a success is a compromised account.
- *Logic:* A successful login correlated with a brute-force alert from the same IP, or on the same account, within 10 minutes.
- *False positives:* Both halves are required and tied by IP or username; an unrelated login after an attack does not fire.
- *Next improvement:* Chain takeover with a later bulk export or price override for a level-15 alert.

## UC04 - Impossible travel

**Where:** web01 + phone + laptop VPN  |  **ATT&CK:** T1078 Valid Accounts  |  **Strongest alert:** 110401 (level 12)

1. On web01: `sudo portal/deploy/start-uc04-tunnel.sh`. It prints a temporary `https://...trycloudflare.com` address that reaches only the sign-in pages.
2. On your phone (mobile data, Wi-Fi off) open `<address>/login` and sign in as `pilgrim0042`.
3. On the laptop, connect Proton VPN Free (any country) and sign in as the same account through the same address. This fires 110401.
4. Disconnect the VPN and stop the tunnel (Ctrl+C).
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110401`.

**Key points:**
- *Why here:* Pilgrims log in from everywhere, so 'abroad' means nothing; two countries in an hour on one account does.
- *Logic:* Two successful logins for the same account from different countries within one hour (GeoIP on the source IP).
- *False positives:* Corporate VPN egress IPs are a CDB list; the rule needs two successes, not failures.
- *Next improvement:* Add device fingerprint and ASN to tell a travelling pilgrim from a proxy.

## UC05 - Pilgrim record harvesting and authorization probing

**Where:** Laptop browser (portal)  |  **ATT&CK:** T1213 Data from Information Repositories; T1190 (probing access control)  |  **Strongest alert:** 110502 (level 10)

1. Sign in as `staff.ops01` / `Staff#2026`, open **Records** and click 12 different names quickly, which gives 110501.
2. Sign in as `pilgrim0042`, then type `/records/1100`, `/records/1101` ... `/records/1104` in the address bar. Each returns 403 and the fifth fires 110502.
3. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110501 or rule.id:110502`.

**Key points:**
- *Why here:* Staff accounts can open any pilgrim record; harvesting them is how passport data leaks.
- *Logic:* 12 different records in 3 minutes by one account, or 5 denied record lookups (IDOR probing).
- *False positives:* Visa reviewers who legitimately page through records are a CDB list.
- *Next improvement:* Per-role baselines: an agency should only ever open its own pilgrims.

## UC06 - SQL injection attempts (edge and application)

**Where:** Laptop browser (portal)  |  **ATT&CK:** T1190 Exploit Public-Facing Application  |  **Strongest alert:** 110602 (level 12)

1. Open **Permit status** and search for `x' OR 'a'='a`.
2. The portal answers 'No permit found' (parameterised query). Wazuh shows 110603 then 110604.
3. Wait 30 seconds. In the browser's address bar open `http://<web01-ip>/?q=x' UNION SELECT NULL--` and press F5 four more times within a minute (5 requests in all), which gives 110602. This burst is counted at the edge only: requests that also reach the search handler become 110604 instead.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110602 or rule.id:110603 or rule.id:110604`.

**Key points:**
- *Why here:* The permit search is public-facing; SQL injection there would expose the whole booking database.
- *Logic:* Edge (nginx URL) and application (search field) detections, correlated when both see the same source within 30 s.
- *False positives:* Grammar-based patterns (UNION SELECT, OR 1=1, time functions), not keywords: a search for O'Brien or the word 'union' does not fire (case UC06-05).
- *Next improvement:* Active response to block the IP after the edge burst rule.

## UC07 - Web shell and web-tier compromise

**Where:** Portal + web01 terminal  |  **ATT&CK:** T1505.003 Web Shell, T1059.004 Unix Shell  |  **Strongest alert:** 110703 (level 15)

1. Portal: upload any small file renamed `passport.php` under **Documents**. It is blocked, which gives 110704.
2. web01: `sudo touch /opt/pilgrim-portal/public/static/uc07-test.php`, then wait until 110701 appears in the dashboard (about 10-15 seconds, FIM realtime). Do not delete the file yet.
3. web01: `sudo -u www-data /usr/bin/id`, which gives 110702 and, because the file alert came first, 110703 (level 15).
4. Clean up only after the alerts are on screen: `sudo rm /opt/pilgrim-portal/public/static/uc07-test.php`.
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110701 or rule.id:110702 or rule.id:110703 or rule.id:110704`.

**Key points:**
- *Why here:* A web shell on the booking server is full control of bookings and pilgrim data.
- *Logic:* FIM sees a script land in the web root; auditd sees the web account run a program; together within 15 min is level 15.
- *False positives:* Only script extensions in the web root; programs the portal needs are a CDB allowlist; deploys never run as www-data.
- *Next improvement:* Quarantine the file automatically with active response.

## UC08 - Package price override abuse (insider fraud)

**Where:** Laptop browser (portal)  |  **ATT&CK:** T1565.001 Stored Data Manipulation  |  **Strongest alert:** 110803 (level 14)

1. Sign in as `staff.ops02` / `Staff#2026`, open **Pricing**, choose the VIP package and set 4500, which gives 110803.
2. As `fin.approver01` / `Finance#2026`, apply 35% off, which gives 110801. Four quick overrides give 110804.
3. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110801 or rule.id:110803 or rule.id:110804`.

**Key points:**
- *Why here:* Price override is a built-in insider-fraud path: a 45,000 SAR VIP package sold for 4,500.
- *Logic:* Big discounts (30%+), overrides by non-approvers, both together (level 14), and 4 overrides in 10 minutes.
- *False positives:* Finance approvers are a CDB list owned by Finance; small goodwill discounts stay as an audit trail.
- *Next improvement:* Require a booking reference and flag overrides on the operator's own bookings.

## UC09 - Bulk export of pilgrim data

**Where:** Laptop browser (portal)  |  **ATT&CK:** T1213 Data from Information Repositories  |  **Strongest alert:** 110904 (level 14)

1. Sign in as `agency.in01` / `Agency#2026` (the largest agency, 1,200 pilgrims), open **Export** and **Download CSV**. This gives 110902, or 110904 at night.
2. As `staff.reporting` / `Staff#2026` the same export gives 110901 (approved account).
3. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:110901 or rule.id:110902 or rule.id:110904`.

**Key points:**
- *Why here:* A manifest of names and passports is exactly what fake-Hajj-package scammers buy.
- *Logic:* 1,000+ records in one export; escalates for non-approved accounts and for off-hours (10 pm - 6 am).
- *False positives:* Approved exporters are a CDB list owned by the Data Protection Officer.
- *Next improvement:* Daily cumulative-volume check for many small exports.

## UC10 - Phishing attachment runs (HTA, script, Office spawning a shell)

**Where:** Windows 10 VM  |  **ATT&CK:** T1566.001 Spearphishing Attachment, T1204.002 Malicious File, T1218.005 Mshta  |  **Strongest alert:** 111003 (level 13)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM, open Notepad and save this as `C:\Users\<you>\Downloads\lab.hta`: `<html><body>Pilgrim lab test<script>window.close()</script></body></html>`
3. Double-click it (it opens and closes), which gives 111001.
4. Save `WScript.Echo("Pilgrim lab test");` as `Downloads\invoice.js` and double-click it, which gives 111002.
5. 111003 needs Office: if it is installed, run Atomic Red Team T1204.002 on the lab VM; otherwise show regression case UC10-03.
6. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111001 or rule.id:111002 or rule.id:111003`.

**Key points:**
- *Why here:* Staff live in their inbox in season; one click on a fake visa or Nusuk invoice is the usual first step.
- *Logic:* mshta or a script host running from Downloads/Temp/Outlook cache, or Office starting a shell.
- *False positives:* Scope is user-download locations only; IT logon scripts run from netlogon or Program Files.
- *Next improvement:* Send the attachment hash to the VirusTotal integration already on the manager.

## UC11 - Obfuscated PowerShell and download cradles

**Where:** Windows 10 VM  |  **ATT&CK:** T1059.001 PowerShell, T1027 Obfuscated Files, T1105 Ingress Tool Transfer  |  **Strongest alert:** 111103 (level 12)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM, in PowerShell:
3. `$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'pilgrim lab'")); powershell -enc $b` gives 111101 (it just prints a line).
4. `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/none')"` gives 111102, and 111103 from the script block. Nothing is listening on 127.0.0.1, so it only prints a connection error.
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111101 or rule.id:111102 or rule.id:111103`.

**Key points:**
- *Why here:* Almost every Windows intrusion uses PowerShell to hide its command or pull the next stage.
- *Logic:* Encoded or hidden PowerShell, and download cradles (download + Invoke-Expression) on the command line or in the decoded script block.
- *False positives:* SCCM and Intune are excluded by parent process; cradle rules need both the download and iex.
- *Next improvement:* PowerShell transcription to a protected share.

## UC12 - Built-in Windows tools used as downloaders (LOLBins)

**Where:** Windows 10 VM  |  **ATT&CK:** T1105 Ingress Tool Transfer, T1140 Deobfuscate/Decode, T1197 BITS Jobs, T1218.010/.011, T1036.003  |  **Strongest alert:** 111206 (level 13)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM: `certutil -urlcache -split -f http://127.0.0.1/none.txt C:\Users\Public\none.txt` gives 111201 (the download fails; Defender may also block it, which is a bonus alert).
3. `copy C:\Windows\System32\certutil.exe C:\Users\Public\cu.exe` then `C:\Users\Public\cu.exe -?` gives 111206. Delete `cu.exe` afterwards.
4. `bitsadmin /transfer pplab /download /priority normal http://127.0.0.1/none.txt C:\Users\Public\none.txt` gives 111203.
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111201 or rule.id:111203 or rule.id:111206`.

**Key points:**
- *Why here:* Attackers use Microsoft's own tools so antivirus stays quiet.
- *Logic:* Abuse syntax of certutil, bitsadmin, regsvr32, rundll32; tools identified by the PE OriginalFileName so renaming does not hide them.
- *False positives:* certutil -dump / -hashfile stay quiet; our rules hang under Wazuh's 92075/92018 so one event gives one alert.
- *Next improvement:* Correlate the download with a process started from the downloaded path.

## UC13 - Persistence through registry autorun keys

**Where:** Windows 10 VM  |  **ATT&CK:** T1547.001 Registry Run Keys / Startup Folder  |  **Strongest alert:** 111302 (level 12)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM: `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PilgrimLab /t REG_SZ /d "C:\Users\Public\lab.exe" /f` gives 111302 (the file does not need to exist).
3. Clean up: `reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PilgrimLab /f`.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111302`.

**Key points:**
- *Why here:* Malware wants to survive the end-of-shift reboot; a Run key is the easiest way.
- *Logic:* Run-key writes, plus Winlogon and policy Run keys; level 12 when the value points to a user folder or a script host.
- *False positives:* Installers (msiexec, setup, OneDrive) are excluded by image; Program Files targets stay medium.
- *Next improvement:* Add the Startup folder via Sysmon file events.

## UC14 - Persistence through a scheduled task

**Where:** Windows 10 VM  |  **ATT&CK:** T1053.005 Scheduled Task  |  **Strongest alert:** 111402 (level 12)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM: `schtasks /create /tn PilgrimLab /tr "C:\Users\Public\lab.exe" /sc once /st 23:59 /f` gives 111402 (Sysmon) and 111401 (4698).
3. Clean up: `schtasks /delete /tn PilgrimLab /f`.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111401 or rule.id:111402`.

**Key points:**
- *Why here:* A new scheduled task gives an attacker persistence and SYSTEM rights.
- *Logic:* Task created (4698) or schtasks /create whose action runs from a user folder or through a script host.
- *False positives:* Vendor updaters run from Program Files; admin scripts belong in a protected folder.
- *Next improvement:* Alert on tasks created over the network as lateral movement.

## UC15 - Privileged group changes (backdoor administrator)

**Where:** Windows 10 VM  |  **ATT&CK:** T1098 Account Manipulation, T1136.001 Create Local Account  |  **Strongest alert:** 111503 (level 14)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM (elevated): `net user pplab01 Lab#2026x /add` then `net localgroup administrators pplab01 /add` gives 111503.
3. Clean up: `net user pplab01 /delete`.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111503`.

**Key points:**
- *Why here:* A backdoor admin keeps the intruder in after the first victim's password is reset.
- *Logic:* Admin-group adds by anyone outside the identity team; account created then made admin within 15 min is level 14.
- *False positives:* Identity admins are a CDB list; the chain needs both halves by the same operator.
- *Next improvement:* Active response to disable the new account.

## UC16 - Expired seasonal staff account used

**Where:** Windows 10 VM  |  **ATT&CK:** T1078.003 Valid Accounts: Local Accounts  |  **Strongest alert:** 111601 (level 13)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM (elevated): `net user s1447.ops017 Season#1447 /add` (a name on the list).
3. `runas /user:s1447.ops017 cmd` with the right password gives 111601; with a wrong one, 111602.
4. Clean up: `net user s1447.ops017 /delete`.
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111601 or rule.id:111602`.

**Key points:**
- *Why here:* Hundreds of seasonal accounts are created each season; leftovers are a quiet way in.
- *Logic:* HR's list of expired accounts (CDB); any successful logon is level 13, failures level 10.
- *False positives:* The list is regenerated from HR every season; re-hired staff are removed from it.
- *Next improvement:* Disable the accounts from the same HR export and keep the rule as a safety net.

## UC17 - Privilege escalation on the web server through sudo

**Where:** web01 terminal  |  **ATT&CK:** T1548.003 Sudo and Sudo Caching  |  **Strongest alert:** 111705 (level 15)

1. On the **Ubuntu web VM (web01)**, open a terminal.
2. web01: `printf 'Defaults:portal !lecture\n' > /tmp/pp-uc17 && sudo visudo -cf /tmp/pp-uc17 && sudo install -m 0440 /tmp/pp-uc17 /etc/sudoers.d/pp-uc17-test` gives 111702 (new drop-in; visudo checks the syntax first).
3. web01: `echo 'nobody ALL=(ALL) NOPASSWD: /usr/bin/true' | sudo tee -a /etc/sudoers.d/pp-uc17-test && sudo visudo -c` gives 111703 (`nobody` cannot log in and `true` does nothing).
4. web01: `sudo -u www-data sudo -n true` gives 111704 (www-data is refused).
5. Clean up: `sudo rm /etc/sudoers.d/pp-uc17-test`.
6. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111702 or rule.id:111703 or rule.id:111704`.

**Key points:**
- *Why here:* A web shell runs as www-data; the next step is root, through sudoers or sudo.
- *Logic:* FIM with report_changes reads the diff: an ADDED non-comment line with NOPASSWD or ALL=(ALL) ALL is level 13; sudo by a service account after a web-shell signal is 14-15.
- *False positives:* Comment lines and removals stay low; admins using sudo keep Wazuh's normal levels.
- *Next improvement:* FIM whodata to show which process and user made the change.

## UC18 - Persistence on the web server through cron

**Where:** web01 terminal  |  **ATT&CK:** T1053.003 Cron  |  **Strongest alert:** 111804 (level 13)

1. On the **Ubuntu web VM (web01)**, open a terminal.
2. web01: `echo '*/30 * * * * /usr/bin/true' | sudo crontab -u www-data -` gives 111803.
3. web01: `(sudo crontab -u www-data -l; echo '*/30 * * * * /usr/bin/curl -s http://198.51.100.9/ping -o /dev/null') | sudo crontab -u www-data -` gives 111804. 198.51.100.9 is a documentation address, so the job reaches nothing.
4. Clean up: `sudo crontab -u www-data -r`.
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111803 or rule.id:111804`.

**Key points:**
- *Why here:* A cron job keeps the foothold alive even after the web shell is removed.
- *Logic:* Any cron change; a service-account crontab is level 12; an added job with curl, wget, nc, /dev/tcp or | sh is level 13.
- *False positives:* Only added, non-comment lines are inspected; package updates stay at medium.
- *Next improvement:* Add systemd timers to the FIM paths.

## UC19 - Defence evasion: Defender weakened, event logs wiped

**Where:** Windows 10 VM  |  **ATT&CK:** T1562.001 Disable or Modify Tools, T1070.001 Clear Windows Event Logs  |  **Strongest alert:** 111910 (level 15)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. Windows Security > Virus & threat protection > Manage settings > Real-time protection **Off** gives 111901.
3. Same page > Exclusions > Add folder `C:\Users\Public` gives 111903.
4. In an elevated prompt, `wevtutil cl "Windows PowerShell"` clears one log. On its own that gives 111909 (command) and 111908 (System event 104); because Defender was weakened first, both escalate to 111910 (level 15).
5. Turn real-time protection back on and remove the exclusion.
6. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:111901 or rule.id:111903 or rule.id:111908 or rule.id:111909 or rule.id:111910`.

**Key points:**
- *Why here:* Before ransomware, intruders switch off the antivirus and wipe the logs.
- *Logic:* Defender turned off, exclusions (risky ones higher), tamper attempts, log clearing; logs wiped after Defender was weakened is level 15.
- *False positives:* Any exclusion is 12, only risky ones are 13; turning protection back on does not alert; the chain needs both halves on one host.
- *Next improvement:* Active response to re-enable real-time protection outside change windows.

## UC20 - Credential theft from LSASS memory and registry hives

**Where:** Windows 10 VM  |  **ATT&CK:** T1003.001 LSASS Memory, T1003.002 Security Account Manager  |  **Strongest alert:** 112004 (level 14)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM (elevated): `reg save HKLM\SYSTEM Q:\sys.hiv` with a drive letter that does not exist (Q:). The command fails, nothing is written, and 112004 fires on the command line.
3. LSASS rules: run Atomic Red Team T1003.001 on the lab VM (pick one test). Defender may block it, which also produces Defender alert 62123 next to UC20.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:112004`.

**Key points:**
- *Why here:* Stolen Windows credentials turn one infected PC into access to every system that user has.
- *Logic:* LSASS opened with memory-read rights (access bits, not fixed masks), dump routines in the call stack, comsvcs MiniDump, SAM/SECURITY/SYSTEM hive export.
- *False positives:* Windows and security processes that legitimately read LSASS are excluded by path; query-only access does not match.
- *Next improvement:* Turn on LSA protection and Credential Guard and alert if they are disabled.

## UC21 - Hands-on-keyboard discovery burst

**Where:** Windows 10 VM  |  **ATT&CK:** T1033, T1082, T1016, T1049, T1057, T1087, T1069, T1135, T1482  |  **Strongest alert:** 112111 (level 13)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM, in cmd: `whoami /all`, `hostname`, `ipconfig /all`, `systeminfo`, `net localgroup administrators`. The fifth command gives 112110.
3. Run the UC12 certutil test first and then the five commands, which gives 112111.
4. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:112110 or rule.id:112111`.

**Key points:**
- *Why here:* After the first foothold an intruder asks who am I, where am I and who is admin.
- *Logic:* Discovery commands are classified silently; 5 different tools by one user in 2 minutes alerts; level 13 if the host just had an execution alert.
- *False positives:* One command, or the same tool repeated, stays silent; SCCM, Intune and the Wazuh agent's own SCA scan are excluded by parent - the SCA one was a real false positive found in the lab and tuned.
- *Next improvement:* Add PowerShell discovery cmdlets from script block logging.

## UC22 - Lateral movement through remote services (PsExec and look-alikes)

**Where:** Windows 10 VM  |  **ATT&CK:** T1021.002 SMB/Admin Shares, T1569.002 Service Execution, T1543.003 Windows Service  |  **Strongest alert:** 112205 (level 14)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM (elevated): `sc.exe create PPLab binPath= "cmd.exe /c echo pilgrim-lab"` gives 112201 (the service never starts properly; the install is what is detected).
3. Clean up: `sc.exe delete PPLab`.
4. Optional: with Sysinternals PsExec, `PsExec64.exe -accepteula -s cmd /c whoami` gives 112201, 112203, 112204 and 112205.
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:112201 or rule.id:112203 or rule.id:112204 or rule.id:112205`.

**Key points:**
- *Why here:* Ransomware crews spread to the file and booking servers by installing a remote service, PsExec style.
- *Logic:* Service installs that are remote-execution tools or shell one-liners, their named pipes and child processes; install plus activity within 2 min is level 14.
- *False positives:* Normal installs under Program Files stay at Wazuh's level 5; Defender platform updates are excluded.
- *Next improvement:* Correlate with a network logon from another internal host just before the install.

## UC23 - Pilgrim documents copied to a USB drive

**Where:** Windows 10 VM  |  **ATT&CK:** T1052.001 Exfiltration over USB  |  **Strongest alert:** 112305 (level 14)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. Plug the USB stick into the laptop. In VMware: **VM > Removable Devices >** your stick **> Connect (Disconnect from Host)**. It appears in the VM as a new drive (usually `E:`); if not, set **VM > Settings > USB Controller** to USB 3.1. This gives 112301.
3. In File Explorer open `C:\PilgrimShare`, right-click **PassportScans > Copy**, open the USB drive and paste. This gives 112305.
4. Clean up: delete the folder from the stick, then **VM > Removable Devices >** your stick **> Disconnect**.
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:112301 or rule.id:112305`.

**Key points:**
- *Why here:* Passport scans and visa batches leave on a USB stick: no network, no proxy, no email gateway.
- *Logic:* 10+ files to an external drive in 2 minutes; higher for identity documents; highest when the stick was plugged in during the last 30 minutes.
- *False positives:* One-off copies are silent; holiday photos stay at the lower level; ignore=300 stops alert storms.
- *Next improvement:* Allowlist approved USB serial numbers in a CDB list.

## UC24 - Command-and-control or data theft over DNS

**Where:** Windows 10 VM  |  **ATT&CK:** T1071.004 DNS, T1048 Exfiltration Over Alternative Protocol, T1572 Protocol Tunneling  |  **Strongest alert:** 112402 (level 12)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM, in PowerShell (it only looks up names that do not exist):
3. `1..25 | % { $l = -join (1..40 | % { [char](Get-Random -InputObject (48..57 + 97..122)) }); Resolve-DnsName "$l.example.com" -ErrorAction SilentlyContinue }` gives 112402.
4. `Resolve-DnsName pilgrimlab.oast.fun -ErrorAction SilentlyContinue` gives 112403.
5. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:112402 or rule.id:112403`.

**Key points:**
- *Why here:* Firewalls still allow DNS everywhere; malware uses it when the proxy blocks the web.
- *Logic:* 20+ unique long-label DNS names from one process in 60 s, and lookups of tunnelling or out-of-band services.
- *False positives:* Long labels alone are silent (CDNs use them); known cloud and AV names are excluded; repeats are not a burst.
- *Next improvement:* Add DNS server logs for devices without Sysmon.

## UC25 - Ransomware behaviour against the pilgrim document share

**Where:** Windows 10 VM  |  **ATT&CK:** T1486 Data Encrypted for Impact, T1485 Data Destruction, T1490 Inhibit System Recovery  |  **Strongest alert:** 112506 (level 15)

1. On the **Windows 10 VM**. Where a step says *elevated*, open PowerShell with right-click > **Run as administrator**; otherwise a normal PowerShell or cmd window is fine.
2. On the Windows VM (elevated): `vssadmin delete shadows /for=Q: /quiet` with a drive letter that does not exist. It fails harmlessly and gives 112505.
3. In Explorer, select the 40 synthetic files in `C:\PilgrimShare\PassportScans` and delete them. The 20th deletion gives 112506 (level 15), or 112502 if you skipped the first step.
4. In Notepad, save an empty `README_RESTORE_FILES.txt` in `C:\PilgrimShare`, which gives 112503.
5. Put the files back with `powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1 -SeedShareOnly` (this itself looks like a mass change, which is expected).
6. Check: Wazuh dashboard > **Threat Hunting**, time range *Last 15 minutes*, search `rule.id:112502 or rule.id:112503 or rule.id:112505 or rule.id:112506`.

**Key points:**
- *Why here:* If passport files are encrypted weeks before departure, pilgrims miss their visa windows.
- *Logic:* 20+ changes on the share in 60 s, ransom notes, double extensions, shadow-copy deletion; mass change after shadow deletion on the same host is level 15.
- *False positives:* Single edits are silent; double extensions never match normal saves; listing shadow copies does not alert.
- *Next improvement:* Canary files that sort first, with active response to isolate the host.

