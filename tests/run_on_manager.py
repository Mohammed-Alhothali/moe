#!/usr/bin/env python3
"""Regression suite for the pilgrim detection library - runs ON the Wazuh manager.

Replays every test case in tests/cases/*.json through the manager's own engine using the logtest
socket (the same engine wazuh-logtest uses), one session per case so frequency and correlation
rules behave exactly as in production, and checks that each step ends on the expected rule.

  sudo /var/ossec/framework/python/bin/python3 tests/run_on_manager.py          # all cases
  sudo /var/ossec/framework/python/bin/python3 tests/run_on_manager.py UC02     # one use case

Cases that the logtest socket cannot replay are listed as SKIP and are proven live instead:
  * FIM (syscheck) events      -> create the test file on web01 and watch the alert
  * time-of-day rules (UC09)   -> run only when the manager's clock is in the same window
                                  (working hours 06:00-22:00 vs off-hours) as the case expects
"""
import glob
import json
import re
import os
import socket
import struct
import sys
import time

SOCK = os.environ.get("LOGTEST_SOCKET", "/var/ossec/queue/sockets/logtest")
CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")


def _recv(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("logtest socket closed the connection")
        buf += chunk
    return buf


def logtest(command, parameters):
    msg = json.dumps({"version": 1, "origin": {"name": "pilgrim-lab-tests", "module": "wazuh-logtest"},
                      "command": command, "parameters": parameters}).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    try:
        s.sendall(struct.pack("<I", len(msg)) + msg)
        size = struct.unpack("<I", _recv(s, 4))[0]
        return json.loads(_recv(s, size))
    finally:
        s.close()


def run_case(case):
    token, rules = None, []
    try:
        for ev in case["events"]:
            params = {"event": ev["log"], "log_format": "syslog", "location": ev["location"]}
            if token:
                params["token"] = token
            resp = logtest("log_processing", params)
            if resp.get("error") != 0:
                return False, [f"logtest error: {resp.get('message') or resp}"], rules
            data = resp["data"]
            token = data.get("token", token)
            rule = (data.get("output") or {}).get("rule") or {}
            rules.append(int(rule["id"]) if "id" in rule else None)
    finally:
        if token:
            try:
                logtest("remove_session", {"token": token})
            except Exception:
                pass
    problems = []
    for exp in case["expect"]:
        got = rules[exp["at"] - 1] if exp["at"] <= len(rules) else None
        if got != exp["rule"]:
            problems.append(f"event {exp['at']}: expected {exp['rule']}, got {got}")
    for forbidden in case["forbid"]:
        if forbidden in rules:
            problems.append(f"rule {forbidden} must not fire but did at event {rules.index(forbidden) + 1}")
    return not problems, problems, rules


def _window(hour):
    return "off-hours" if hour >= 22 or hour < 6 else "working hours"


def main():
    if not os.path.exists(SOCK):
        sys.exit(f"logtest socket not found at {SOCK} - run this on the Wazuh manager with sudo")
    only = [a.upper() for a in sys.argv[1:]]
    passed = failed = skipped = 0
    for path in sorted(glob.glob(os.path.join(CASES, "*.json"))):
        for case in json.load(open(path))["cases"]:
            if only and not any(case["id"].startswith(o) for o in only):
                continue
            kinds = {ev["type"] for ev in case["events"]}
            if kinds != {"raw"}:
                skipped += 1
                windows_fim = any(ev["type"] == "fim" and re.match(r"^[a-zA-Z]:\\", ev["data"]["path"])
                                  for ev in case["events"])
                where = "Windows VM" if ("win" in kinds or windows_fim) else "web01"
                what = "Windows event" if "win" in kinds else "FIM event"
                print(f"SKIP {case['id']:8} {case['title']}  ({what} - wazuh-logtest cannot replay it; prove live on the {where})")
                continue
            if "local_hour" in case and _window(case["local_hour"]) != _window(time.localtime().tm_hour):
                skipped += 1
                print(f"SKIP {case['id']:8} {case['title']}  (needs {_window(case['local_hour'])} on the manager)")
                continue
            ok, problems, rules = run_case(case)
            if ok:
                passed += 1
                print(f"PASS {case['id']:8} {case['title']}")
            else:
                failed += 1
                print(f"FAIL {case['id']:8} {case['title']}")
                for p in problems:
                    print(f"       {p}")
                print(f"       final rule per event: {rules}")
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped (live-only)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
