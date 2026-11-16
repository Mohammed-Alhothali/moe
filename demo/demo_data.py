#!/usr/bin/env python3
"""Builds the demo data set: the library's alerts (sample-alerts.ndjson, produced by replaying the regression
cases through the Wazuh analysis engine) mixed with ordinary built-in Wazuh alerts, archived events and
vulnerability states, spread over the last 7 days. Everything is synthetic.
Usage: demo_data.py OUTDIR"""
import datetime, json, os, random, sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
CAT = json.load(open(os.path.join(PROJ, "console", "app", "static", "usecases.json"), encoding="utf-8"))
TECH = CAT["techniques"]
OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
rnd = random.Random(7)
now = datetime.datetime.now(datetime.timezone.utc)
AG = {"win": {"id": "001", "name": "Windows-10", "ip": "192.168.56.131"},
      "web": {"id": "002", "name": "Ubuntu", "ip": "192.168.56.129"},
      "srv": {"id": "000", "name": "wazuh-server"}}


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+0000"


def mitre(ids):
    tactics = []
    for t in ids:
        for tac in (TECH.get(t) or {}).get("tactics", []):
            if tac not in tactics:
                tactics.append(tac)
    return {"id": ids, "tactic": tactics, "technique": [(TECH.get(t) or {}).get("name", t) for t in ids]}


lib = [json.loads(l) for l in open(os.path.join(HERE, "sample-alerts.ndjson"), encoding="utf-8")]
alerts, n = [], 0

# library alerts: most in the last 6 hours (a demo session), some earlier in the week
for i, a in enumerate(lib):
    if a["rule"]["id"] in ("502",):
        continue
    n += 1
    hours = rnd.uniform(0.05, 6) if i % 3 else rnd.uniform(6, 160)
    dt = now - datetime.timedelta(hours=hours)
    a["timestamp"] = ts(dt)
    a["id"] = f"{int(dt.timestamp())}.{100000 + n}"
    a["rule"]["mitre"] = mitre(a["rule"].get("mitre", {}).get("id", []))
    a["rule"].setdefault("groups", ["pilgrim"])
    a["manager"] = {"name": "wazuh-server"}
    alerts.append(a)

NOISE = [  # rule id, level, description, groups, mitre ids, agent, extra
    ("60106", 3, "Windows logon success.", ["windows", "authentication_success"], ["T1078"], "win", {}),
    ("60227", 3, "A new external device was recognized by the system.", ["windows"], [], "win", {}),
    ("92900", 12, "Lsass process was accessed by C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
     ["sysmon", "sysmon_eid10_detections"], ["T1003.001"], "win", {}),
    ("61104", 3, "Service startup type was changed", ["windows", "policy_changed"], ["T1543.003"], "win", {}),
    ("5501", 3, "PAM: Login session opened.", ["pam", "syslog", "authentication_success"], ["T1078"], "web", {}),
    ("5502", 3, "PAM: Login session closed.", ["pam", "syslog"], [], "web", {}),
    ("5402", 3, "Successful sudo to ROOT executed.", ["syslog", "sudo"], ["T1548.003"], "web", {}),
    ("550", 7, "Integrity checksum changed.", ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"], [], "web",
     {"syscheck": {"path": "/etc/hosts", "event": "modified", "mode": "realtime"}}),
    ("554", 5, "File added to the system.", ["ossec", "syscheck", "syscheck_entry_added", "syscheck_file"], [], "win",
     {"syscheck": {"path": "c:\\pilgrimshare\\visas\\batch-17.pdf", "event": "added", "mode": "realtime"}}),
    ("19007", 7, "CIS Microsoft Windows 10 Enterprise Benchmark v3.0.0: Ensure 'Minimum password length' is set to '14 or more character(s)'.",
     ["sca"], [], "win", {}),
    ("19004", 7, "SCA summary: CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0: Score less than 50% (42)", ["sca"], [], "web", {}),
    ("31101", 5, "Web server 400 error code.", ["web", "accesslog", "attack"], [], "web", {}),
    ("502", 3, "Wazuh server started.", ["ossec"], [], "srv", {}),
    ("23505", 10, "CVE-2024-6387 affects openssh-server", ["vulnerability-detector"], [], "web", {}),
]
weights = [30, 6, 3, 5, 25, 25, 10, 6, 6, 40, 3, 12, 2, 2]
for k in range(900):
    rid, lvl, desc, groups, mids, who, extra = rnd.choices(NOISE, weights)[0]
    dt = now - datetime.timedelta(hours=rnd.uniform(0.01, 168) ** 1.0)
    n += 1
    a = {"timestamp": ts(dt), "rule": {"level": lvl, "description": desc, "id": rid, "groups": groups, "firedtimes": 1,
                                       "mail": False, **({"mitre": mitre(mids)} if mids else {})},
         "agent": AG[who], "manager": {"name": "wazuh-server"}, "id": f"{int(dt.timestamp())}.{200000 + n}",
         "decoder": {"name": "windows_eventchannel" if who == "win" else "pam" if rid.startswith("55") else "syscheck_integrity_changed" if rid in ("550", "554") else "sca"},
         "location": "EventChannel" if who == "win" else "/var/log/auth.log" if rid.startswith("5") else "sca"}
    a.update(extra)
    if who == "web" and rid in ("5501", "5502", "5402"):
        a["full_log"] = f"{dt.strftime('%b %d %H:%M:%S')} web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)"
        a["data"] = {"srcuser": "ubuntu", "dstuser": "root"}
    if who == "win" and rid == "60106":
        a["data"] = {"win": {"system": {"eventID": "4624", "computer": "WIN10-LAB", "channel": "Security"},
                             "eventdata": {"targetUserName": "windows", "logonType": "2"}}}
    alerts.append(a)

alerts.sort(key=lambda a: a["timestamp"])
with open(os.path.join(OUT, "alerts.ndjson"), "w", encoding="utf-8") as f:
    for a in alerts:
        f.write(json.dumps(a) + "\n")

# archives: every alert as an event, plus ordinary events that matched no rule
logs = []
for a in alerts:
    e = {k: v for k, v in a.items() if k != "rule"}
    if a["rule"]["level"] >= 3:
        e["rule"] = a["rule"]
    logs.append(e)
PROCS = ["C:\\Windows\\System32\\svchost.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\RuntimeBroker.exe", "C:\\Windows\\System32\\conhost.exe"]
for k in range(1600):
    dt = now - datetime.timedelta(hours=rnd.uniform(0.0, 30))
    n += 1
    if k % 3:
        p = rnd.choice(PROCS)
        data = {"win": {"system": {"eventID": "1", "computer": "WIN10-LAB", "channel": "Microsoft-Windows-Sysmon/Operational",
                                   "providerName": "Microsoft-Windows-Sysmon"},
                        "eventdata": {"image": p.replace("\\", "\\\\"), "commandLine": f"\\\"{p}\\\" --type=renderer".replace("\\", "\\\\"),
                                      "user": "WIN10-LAB\\\\windows", "parentImage": "C:\\\\Windows\\\\explorer.exe"}}}
        logs.append({"timestamp": ts(dt), "agent": AG["win"], "manager": {"name": "wazuh-server"}, "id": f"{int(dt.timestamp())}.{300000 + n}",
                     "decoder": {"name": "windows_eventchannel"}, "location": "EventChannel", "data": data,
                     "full_log": json.dumps(data)[:600]})
    else:
        line = rnd.choice([
            f"{dt.strftime('%b %d %H:%M:%S')} web01 pilgrim-portal[812]: {{\"event\":\"page_view\",\"username\":\"pilgrim{rnd.randint(1,999):04d}\",\"path\":\"/bookings\",\"srcip\":\"10.0.0.{rnd.randint(2,200)}\"}}",
            f"{dt.strftime('%b %d %H:%M:%S')} web01 systemd[1]: Started Daily apt download activities.",
            f"10.0.0.{rnd.randint(2,200)} - - [{dt.strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"GET /static/css/site.css HTTP/1.1\" 200 5120 \"-\" \"Mozilla/5.0\""])
        logs.append({"timestamp": ts(dt), "agent": AG["web"], "manager": {"name": "wazuh-server"}, "id": f"{int(dt.timestamp())}.{300000 + n}",
                     "decoder": {"name": "pilgrim-portal" if "pilgrim-portal" in line else "nginx-accesslog" if "GET" in line else "systemd"},
                     "location": "/var/log/pilgrim-portal/portal.log" if "pilgrim-portal" in line else "/var/log/nginx/access.log" if "GET" in line else "journald",
                     "full_log": line})
logs.sort(key=lambda e: e["timestamp"])
with open(os.path.join(OUT, "archives.ndjson"), "w", encoding="utf-8") as f:
    for e in logs:
        f.write(json.dumps(e) + "\n")

vulns = []
for aid, pkgs in (("002", [("openssh-server", "1:9.6p1-3ubuntu13", "CVE-2024-6387", "High", 8.1),
                           ("libexpat1", "2.6.1-2build1", "CVE-2024-45491", "Critical", 9.8),
                           ("curl", "8.5.0-2ubuntu10.1", "CVE-2024-7264", "Medium", 6.5),
                           ("python3.12", "3.12.3-1", "CVE-2024-6232", "Medium", 5.3)]),
                  ("001", [("Microsoft Edge", "128.0.2739.42", "CVE-2024-7971", "High", 8.8),
                           ("7-Zip", "23.01", "CVE-2024-11477", "High", 7.8),
                           ("Notepad++", "8.6.2", "CVE-2024-3292", "Low", 3.3)])):
    for name, ver, cve, sev, score in pkgs:
        vulns.append({"agent": {"id": aid}, "package": {"name": name, "version": ver},
                      "vulnerability": {"id": cve, "severity": sev, "score": {"base": score}}})
with open(os.path.join(OUT, "vulns.ndjson"), "w", encoding="utf-8") as f:
    for v in vulns:
        f.write(json.dumps(v) + "\n")
print(f"alerts {len(alerts)} ({len(lib)} from the library engine run), archived events {len(logs)}, vulnerabilities {len(vulns)}")
