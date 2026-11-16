#!/usr/bin/env python3
"""Static checks for the library's Wazuh rules (run before deploying; no Wazuh needed).

  python3 tests/lint_rules.py

Checks
  * every rules file is well-formed XML
  * no <rule> is nested inside another rule (a silent, easy-to-make mistake)
  * every rule ID is unique and inside the library's 11xxxx range
  * every if_sid / if_matched_sid points to a library rule or a built-in rule (< 100000)
  * every detection rule (UC01+) has a description starting with its UC number and a MITRE block
  * every library group used in if_group / if_matched_group is defined by a rule loaded EARLIER
    (Wazuh links group correlation at load time; a later rule with that group is silently ignored)
  * no rule is reached by a correlation group only because its group name CONTAINS that name
    (Wazuh matches group names as substrings)
  * no plain (osregex) field uses alternation inside parentheses, which osregex rejects - use type="pcre2"
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wazuh", "rules")


def main():
    problems, rules = [], {}
    for path in sorted(glob.glob(os.path.join(RULES, "pp-*.xml"))):
        name = os.path.basename(path)
        try:
            root = ET.fromstring("<root>" + open(path, encoding="utf-8").read() + "</root>")
        except ET.ParseError as exc:
            problems.append(f"{name}: not well-formed XML ({exc})")
            continue
        for rule in root.iter("rule"):
            rid = rule.get("id", "")
            if rule.find(".//rule") is not None:
                problems.append(f"{name}: rule {rid} contains a nested <rule>")
            if not re.fullmatch(r"11\d{4}", rid):
                problems.append(f"{name}: rule id '{rid}' is outside the library range 11xxxx")
            if rid in rules:
                problems.append(f"{name}: rule {rid} is duplicated (also in {rules[rid][0]})")
            rules[rid] = (name, rule)
    for rid, (name, rule) in rules.items():
        for tag in ("if_sid", "if_matched_sid"):
            for ref in rule.findall(tag):
                for target in re.split(r"[,\s]+", (ref.text or "").strip()):
                    if target and int(target) >= 100000 and target not in rules:
                        problems.append(f"{name}: rule {rid} {tag} {target} does not exist")
        uc = int(rid[2:4]) if len(rid) == 6 else 0
        if uc >= 1:
            desc = (rule.findtext("description") or "").strip()
            if not desc.startswith(f"UC{uc:02d}"):
                problems.append(f"{name}: rule {rid} description should start with 'UC{uc:02d}'")
            if rule.find("mitre") is None and "pp_tuning" not in "".join(g.text or "" for g in rule.findall("group")):
                problems.append(f"{name}: rule {rid} has no <mitre> block")
    # group checks, in Wazuh load order (file name order, then position in the file)
    defined, order = {}, []
    for rid, (name, rule) in rules.items():
        order.append((name, rid, rule))
    seen = set()
    all_groups = set()
    for name, rid, rule in order:
        for tag in ("if_group", "if_matched_group"):
            for ref in rule.findall(tag):
                for g in (ref.text or "").strip().split("|"):
                    if g.startswith("pp_") and g not in seen:
                        problems.append(f"{name}: rule {rid} {tag} '{g}' is not defined by any earlier rule")
        for gtag in rule.findall("group"):
            for g in (gtag.text or "").split(","):
                g = g.strip()
                if g.startswith("pp_"):
                    seen.add(g)
                    all_groups.add(g)
    used = set()
    for name, rid, rule in order:
        for tag in ("if_group", "if_matched_group"):
            for ref in rule.findall(tag):
                used.update(g for g in (ref.text or "").strip().split("|") if g.startswith("pp_"))
    for name, rid, rule in order:
        groups = {g.strip() for gt in rule.findall("group") for g in (gt.text or "").split(",") if g.strip()}
        for u in used:
            if u not in groups and any(u in g for g in groups):
                problems.append(f"{name}: rule {rid} would be caught by '{u}' through a longer group name "
                                f"(Wazuh matches group names as substrings) - rename the group")
    for rid, (name, rule) in rules.items():
        for f in rule.findall("field"):
            if f.get("type", "osregex") == "osregex" and re.search(r"\([^)]*\|", f.text or ""):
                problems.append(f"{name}: rule {rid} field {f.get('name')} uses (a|b) in osregex - add type=\"pcre2\"")
    for p in problems:
        print("FAIL", p)
    print(f"{len(rules)} rules checked, {len(problems)} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
