# Regression results - Wazuh engine (4.14.9 analysis engine built from source, Wazuh 4.12.0 ruleset)

161 passed, 0 failed

| Case | Type | Result | Final rules per event |
|---|---|---|---|
| UC01-01 One account fires 10 booking attempts in a minute -> 110101 | positive | PASS | 110013 110013 110013 110013 110013 110013 110013 110013 110013 110101 |
| UC01-02 15 attempts from one IP, rotating accounts -> 110102 | positive | PASS | 110013 110013 110013 110013 110013 110013 110013 110013 110013 110013 110013 110013 110013 ... |
| UC01-03 9 attempts stays under the threshold (no alert) | negative | PASS | 110013 110013 110013 110013 110013 110013 110013 110013 110013 |
| UC01-04 Load-test agent on the trusted list is ignored | negative | PASS | 110013 110013 110013 110013 110013 110013 110013 110013 110013 110013 110013 110013 |
| UC02-01 Wrong passwords for 8 different accounts from one IP -> 110201 | positive | PASS | 110011 110011 110011 110011 110011 110011 110011 110201 |
| UC02-02 5 non-existent accounts from one IP -> 110202 (high confidence) | positive | PASS | 110012 110012 110012 110012 110202 |
| UC02-03 6 wrong passwords for one agency account -> 110203 | positive | PASS | 110011 110011 110011 110011 110011 110203 |
| UC02-04 Hotel NAT: 7 pilgrims mistype passwords from one IP (no alert) | negative | PASS | 110011 110011 110011 110011 110011 110011 110011 |
| UC02-05 Internal scanner on the trusted list is ignored | negative | PASS | 110012 110012 110012 110012 110012 110012 110012 110012 110012 |
| UC02-06 Tuning: nginx 401 for a failed sign-in is absorbed (no duplicate 31101 alert) | negative | PASS | 110021 |
| UC02-07 Tuning keeps other 4xx: a scanner probing /wp-admin still raises 31101 | positive | PASS | 31101 |
| UC03-01 Stuffing from an IP, then a success from that IP -> 110301 | positive | PASS | 110012 110012 110012 110012 110202 110301 |
| UC03-02 Password guessing on an account, attacker switches IP, then success -> 110302 | positive | PASS | 110011 110011 110011 110011 110011 110203 110302 |
| UC03-03 Unrelated user logs in from another IP after an attack (no takeover alert) | negative | PASS | 110012 110012 110012 110012 110202 110010 |
| UC04-01 Same account: Saudi Arabia, then the Netherlands within the hour -> 110401 | positive | PASS | 110010 110401 |
| UC04-02 Two logins from the same country (no alert) | negative | PASS | 110010 110010 |
| UC04-03 Second login via the corporate VPN exit (allowlisted, no alert) | negative | PASS | 110010 110010 |
| UC05-01 Staff opens 12 different pilgrim records in minutes -> 110501 | positive | PASS | 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 110501 |
| UC05-02 Same record re-opened 12 times (no alert) | negative | PASS | 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 |
| UC05-03 Approved bulk reviewer during a visa peak (no alert) | negative | PASS | 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 110014 ... |
| UC05-04 Pilgrim walks other pilgrims' record IDs and is denied 5 times -> 110502 | positive | PASS | 110015 110015 110015 110015 110502 |
| UC05-05 Tuning: nginx 403 for a refused record is absorbed (no duplicate 31101 alert) | negative | PASS | 110022 |
| UC06-01 Encoded tautology in the URL -> 110601 | positive | PASS | 110601 |
| UC06-02 UNION SELECT and time-based probes, 5 in a row from one IP -> 110602 | positive | PASS | 110601 110601 110601 110601 110602 |
| UC06-03 Injection grammar in the decoded search parameter -> 110603 | positive | PASS | 110603 |
| UC06-04 Same request seen by the app and then the edge -> 110604 | positive | PASS | 110603 110604 |
| UC06-06 Found live: 5 injection searches seen by app then edge -> burst 110605 | positive | PASS | 110603 110604 110603 110604 110603 110604 110603 110604 110603 110605 |
| UC06-05 Legitimate searches with an apostrophe or the word union (no alert) | negative | PASS | 110016 31100 110016 31106 |
| UC07-01 Script file appears in the portal web root -> 110701 | positive | PASS | 110701 |
| UC07-02 Web service account (www-data) executes a program -> 110702 | positive | PASS | 110702 |
| UC07-03 Script dropped, then the web tier runs a command -> 110703 (level 15) | positive | PASS | 110701 110703 |
| UC07-04 Static asset (CSS) change in the web root (no alert) | negative | PASS | 550 |
| UC07-05 Upload allowlist blocks a .php disguised as a passport scan -> 110704 | positive | PASS | 110704 |
| UC07-06 Wrong document type (.docx) rejected - user error, not an attack (no alert) | negative | PASS | 110019 |
| UC08-01 Finance approver gives a 35% discount -> 110801 | positive | PASS | 110801 |
| UC08-02 Non-approver changes a price (10%) -> 110802 | positive | PASS | 110802 |
| UC08-03 Non-approver gives a 90% discount -> 110803 (level 14) | positive | PASS | 110803 |
| UC08-04 Approver makes 4 small overrides in 10 minutes -> 110804 | positive | PASS | 110017 110017 110017 110804 |
| UC08-05 Approver gives a 10% goodwill discount (audit trail only) | negative | PASS | 110017 |
| UC09-01 Approved reporting account exports 1,500 records in working hours -> 110901 | positive | PASS | 110901 |
| UC09-02 Largest agency exports its own 1,200 pilgrims -> 110902 (not an approved exporter) | positive | PASS | 110902 |
| UC09-03 Approved account exports at 23:00 -> 110903 | positive | PASS | 110903 |
| UC09-04 Non-approved account exports at 02:00 -> 110904 (level 14) | positive | PASS | 110904 |
| UC09-05 Agency exports its own 300 pilgrims (no alert) | negative | PASS | 110018 |
| UC10-01 mshta opens an HTA from Downloads -> 111001 | positive | PASS | 111001 |
| UC10-02 wscript runs a .js extracted from a zipped invoice in Temp -> 111002 | positive | PASS | 111002 |
| UC10-03 Word starts PowerShell -> 111003 | positive | PASS | 111003 |
| UC10-04 IT logon script from the netlogon share (no alert) | negative | PASS | 61603 |
| UC10-05 Vendor help file opened with mshta from Program Files (no alert) | negative | PASS | 61603 |
| UC11-01 Hidden PowerShell with an encoded command -> 111101 | positive | PASS | 111101 |
| UC11-02 Download cradle on the command line -> 111102 | positive | PASS | 111102 |
| UC11-03 Cradle seen in the decoded script block (4104) -> 111103 | positive | PASS | 111103 |
| UC11-04 SCCM agent running an encoded command (excluded by parent, no alert) | negative | PASS | 61603 |
| UC11-05 Admin downloads a report without executing it (no cradle alert) | negative | PASS | 92021 |
| UC12-01 certutil downloads an EXE (Wazuh 92075 matches first, UC12 child wins) -> 111201 | positive | PASS | 111201 |
| UC12-02 certutil downloads a PowerShell script (gap in Wazuh 92075) -> 111201 | positive | PASS | 111201 |
| UC12-03 certutil decodes base64 into an EXE (Wazuh 92018 matches first, UC12 child wins) -> 111202 | positive | PASS | 111202 |
| UC12-04 certutil -decodehex into a DLL (gap in Wazuh 92018) -> 111202 | positive | PASS | 111202 |
| UC12-05 bitsadmin transfer job -> 111203 | positive | PASS | 111203 |
| UC12-06 regsvr32 loads a remote scriptlet -> 111204 | positive | PASS | 111204 |
| UC12-07 rundll32 opens a URL -> 111205 | positive | PASS | 111205 |
| UC12-08 certutil copied to Users\Public under another name -> 111206 | positive | PASS | 111206 |
| UC12-11 renamed certutil decodes into an EXE (Wazuh 92016 -> 92017 path) -> 111206 | positive | PASS | 111206 |
| UC12-09 certutil dumping a certificate (no alert) | negative | PASS | 61603 |
| UC12-10 admin checks a file hash with certutil (no alert) | negative | PASS | 61603 |
| UC13-01 Run key launching an EXE from AppData -> 111302 | positive | PASS | 111302 |
| UC13-02 Run key written by a normal application in Program Files -> 111301 (medium) | positive | PASS | 111301 |
| UC13-04 Winlogon Userinit hijacked to also start a file from Users\Public -> 111302 | positive | PASS | 111302 |
| UC13-05 Policies\Explorer\Run entry pointing at Program Files -> 111303 (medium) | positive | PASS | 111303 |
| UC13-03 Installer (msiexec) writes a Run key (no alert) | negative | PASS | 92300 |
| UC14-01 Task 4698 runs an EXE from AppData -> 111401 | positive | PASS | 111401 |
| UC14-02 schtasks /create with a hidden PowerShell action -> 111402 | positive | PASS | 111402 |
| UC14-03 Updater task in Program Files (no alert) | negative | PASS | 60228 |
| UC15-01 Non-approved operator adds a member to Administrators -> 111501 | positive | PASS | 111501 |
| UC15-02 Approved identity admin adds a member (stays at Wazuh default 60154) | negative | PASS | 60154 |
| UC15-03 Member added to Remote Desktop Users -> 111502 | positive | PASS | 111502 |
| UC15-04 Account created then made admin by the same operator -> 111503 | positive | PASS | 60109 111503 |
| UC16-01 Expired seasonal account logs on -> 111601 | positive | PASS | 111601 |
| UC16-02 Failed logon with an expired seasonal account -> 111602 | positive | PASS | 111602 |
| UC16-03 Normal staff logon (no alert) | negative | PASS | 92651 |
| UC17-01 /etc/sudoers edited (comment only) -> 111701 | positive | PASS | 111701 |
| UC17-02 New drop-in file in /etc/sudoers.d -> 111702 | positive | PASS | 111702 |
| UC17-03 Drop-in edited to add a NOPASSWD rule -> 111703 | positive | PASS | 111703 |
| UC17-04 Full ALL=(ALL:ALL) ALL granted in /etc/sudoers -> 111703 | positive | PASS | 111703 |
| UC17-05 NOPASSWD only inside a comment stays at 111701 (FP control) | negative | PASS | 111701 |
| UC17-06 Web service account runs sudo (classic syslog time) -> 111704 | positive | PASS | 111704 |
| UC17-07 Web service account runs sudo (Ubuntu 24.04 ISO time) -> 111704 | positive | PASS | 111704 |
| UC17-08 Script planted in the web root, run, then sudo by www-data -> 111705 | positive | PASS | 110701 110703 111705 |
| UC17-10 Web account runs an unexpected program, then sudo -> 111706 | positive | PASS | 110702 111706 |
| UC17-09 Administrator uses sudo normally (no UC17 alert) | negative | PASS | 5403 |
| UC18-01 /etc/crontab edited -> 111801 | positive | PASS | 111801 |
| UC18-02 New file in /etc/cron.d -> 111802 | positive | PASS | 111802 |
| UC18-03 Crontab created for www-data -> 111803 | positive | PASS | 111803 |
| UC18-04 cron.d job that downloads with curl -> 111804 | positive | PASS | 111804 |
| UC18-05 www-data crontab gets a reverse-shell style job -> 111804 | positive | PASS | 111804 |
| UC18-06 Downloader line that is commented out stays at 111801 (FP control) | negative | PASS | 111801 |
| UC19-01 Real-time protection turned off (5001) -> 111901 | positive | PASS | 111901 |
| UC19-02 Antivirus scanning disabled logged as a warning (5012) -> 111901 | positive | PASS | 111901 |
| UC19-03 Exclusion added for a business folder -> 111902 | positive | PASS | 111902 |
| UC19-04 Exclusion added for C:\Users\Public -> 111903 | positive | PASS | 111903 |
| UC19-05 Whole-drive exclusion -> 111903 | positive | PASS | 111903 |
| UC19-06 Tamper Protection blocked a change (5013) -> 111904 | positive | PASS | 111904 |
| UC19-17 Found live: turning protection back ON logs 5013 '= 0 -> 0' (no alert) | negative | PASS | 62100 |
| UC19-07 Add-MpPreference exclusion from PowerShell -> 111905 | positive | PASS | 111905 |
| UC19-08 reg.exe sets DisableAntiSpyware policy -> 111905 | positive | PASS | 111905 |
| UC19-09 sc stop WinDefend -> 111905 | positive | PASS | 111905 |
| UC19-10 Set-MpPreference disables real-time monitoring (Wazuh 92008 path) -> 111906 | positive | PASS | 111906 |
| UC19-11 Security log cleared (1102) -> 111907 | positive | PASS | 111907 |
| UC19-12 Windows PowerShell log cleared (System 104) -> 111908 | positive | PASS | 111908 |
| UC19-18 wevtutil cl typed in PowerShell (quoted path) -> 111909 | positive | PASS | 111909 |
| UC19-13 wevtutil cl from the command line -> 111909 | positive | PASS | 111909 |
| UC19-14 Defender turned off, then the Security log cleared -> 111910 | positive | PASS | 111901 111910 |
| UC19-15 Real-time protection turned back on (5000) - no UC19 alert | negative | PASS | 62151 |
| UC19-16 Log cleared with no Defender change before it stays 111907 | negative | PASS | 111907 |
| UC20-01 Unknown tool opens LSASS with 0x1010 (Wazuh 92900 path) -> 112001 | positive | PASS | 112001 |
| UC20-02 Full access 0x1fffff that Wazuh 92900 does not list -> 112001 | positive | PASS | 112001 |
| UC20-03 Task Manager dump: MiniDumpWriteDump in the call stack -> 112002 | positive | PASS | 112002 |
| UC20-04 rundll32 comsvcs.dll MiniDump -> 112003 | positive | PASS | 112003 |
| UC20-05 reg save of the SAM hive (Wazuh 92026 path) -> 112004 | positive | PASS | 112004 |
| UC20-06 reg save of the SYSTEM hive (gap in Wazuh 92026) -> 112004 | positive | PASS | 112004 |
| UC20-07 Defender scanning LSASS (allow-listed path, no alert) | negative | PASS | 61612 |
| UC20-10 Found live: Defender opens LSASS with 0x1010 - Wazuh's 92900 silenced by tuning rule 112009 | negative | PASS | 112009 |
| UC20-08 Query-only access 0x1000 (no alert) | negative | PASS | 61612 |
| UC20-09 Exporting one service key under HKLM\SYSTEM (no alert) | negative | PASS | 92025 |
| UC21-01 Five different discovery tools in a row -> 112110 on the fifth | positive | PASS | 112109 112109 112109 112109 112110 |
| UC21-02 A single discovery command stays silent (classified, counted, no alert) | negative | PASS | 112109 |
| UC21-03 Domain trust discovery -> 112104 | positive | PASS | 112104 |
| UC21-04 Admin re-runs ipconfig five times (same tool, no burst) | negative | PASS | 112109 112109 112109 112109 112109 |
| UC21-05 net user ... /add is left to Wazuh's net.exe rules (not swallowed by the classifier) | positive | PASS | 92039 |
| UC21-06 Burst after a LOLBin download on the same host -> 112111 | positive | PASS | 111201 112109 112109 112109 112109 112111 |
| UC21-07 Inventory commands from the management agent (excluded) | negative | PASS | 61603 61603 61603 61603 61603 |
| UC21-08 Wazuh agent's own SCA scan (found live in the lab: wmic + net as SYSTEM) - no burst | negative | PASS | 61603 61603 92031 92031 92031 92031 |
| UC21-09 Admin runs several net.exe queries; net1.exe children are not counted again - no burst | negative | PASS | 112109 92031 112109 92031 112109 92031 112109 92031 112109 92031 |
| UC22-01 PsExec service installed -> 112201 | positive | PASS | 112201 |
| UC22-02 smbexec-style service running a cmd one-liner -> 112201 | positive | PASS | 112201 |
| UC22-03 Service binary in C:\Users\Public -> 112202 | positive | PASS | 112202 |
| UC22-04 PSEXESVC named pipe -> 112203 | positive | PASS | 112203 |
| UC22-05 Command started by PSEXESVC -> 112204 | positive | PASS | 112204 |
| UC22-06 Service install, then its pipe -> 112205 | positive | PASS | 112201 112205 |
| UC22-07 Normal software installs a service under Program Files (no UC22 alert) | negative | PASS | 61138 |
| UC22-08 Defender platform update re-registers its service (no UC22 alert) | negative | PASS | 61138 |
| UC23-01 USB stick connected -> 112301 | positive | PASS | 112301 |
| UC23-02 Ten holiday photos copied to E: -> 112303 (bulk, not identity documents) | positive | PASS | 112302 112302 112302 112302 112302 112302 112302 112302 112302 112303 |
| UC23-03 Ten passport scans copied to E: -> 112304 | positive | PASS | 112302 112302 112302 112302 112302 112302 112302 112302 112302 112304 |
| UC23-04 USB plugged in, then passport scans copied -> 112305 | positive | PASS | 112301 112302 112302 112302 112302 112302 112302 112302 112302 112302 112305 |
| UC23-05 Three files copied to USB (below threshold, silent) | negative | PASS | 112302 112302 112302 |
| UC24-01 20 unique 40-character subdomains from one process in a minute -> 112402 | positive | PASS | 112401 112401 112401 112401 112401 112401 112401 112401 112401 112401 112401 112401 112401 ... |
| UC24-02 Lookup of an ngrok tunnel host -> 112403 | positive | PASS | 112403 |
| UC24-03 Lookup of an interactsh / OAST host -> 112403 | positive | PASS | 112403 |
| UC24-04 Same long name repeated 20 times (cache refresh, no burst) | negative | PASS | 112401 112401 112401 112401 112401 112401 112401 112401 112401 112401 112401 112401 112401 ... |
| UC24-05 Long AWS load-balancer names are excluded (no burst) | negative | PASS | 61650 61650 61650 61650 61650 61650 61650 61650 61650 61650 61650 61650 61650 61650 61650  ... |
| UC25-01 20 files deleted from the share in a minute -> 112502 | positive | PASS | 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 ... |
| UC25-02 Ransom note written to the share -> 112503 | positive | PASS | 112503 |
| UC25-03 Documents renamed to .pdf.locked -> 112504 | positive | PASS | 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 ... |
| UC25-04 vssadmin delete shadows -> 112505 | positive | PASS | 112505 |
| UC25-11 Found live: vssadmin typed in PowerShell (quoted program path) -> 112505 | positive | PASS | 112505 |
| UC25-05 wmic shadowcopy delete -> 112505 | positive | PASS | 112505 |
| UC25-06 bcdedit disables recovery -> 112505 | positive | PASS | 112505 |
| UC25-07 Shadow copies deleted, then mass encryption of the share -> 112506 | positive | PASS | 112505 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 112501 ... |
| UC25-08 Listing shadow copies (no alert) | negative | PASS | 61603 |
| UC25-09 Five documents edited by staff (below threshold, silent) | negative | PASS | 112501 112501 112501 112501 112501 |
