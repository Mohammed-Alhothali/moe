# Notes on the Wazuh 4.x analysis engine

These are behaviours this library relies on or had to work around. Each one was confirmed in the Wazuh source
code, in the engine built from source, or live in the lab, and each one changed how a rule is written.

1. **A level-0 rule never feeds correlation.** The engine stops before storing the event, so a `frequency` rule built
   on a level-0 rule can never fire. Base rules are therefore level 2 (counted, not shown) or 3 (kept as an audit trail).
2. **Level-0 rules are tried before all their siblings** (they are loaded as level 99). Wazuh's level-0 classifiers,
   such as 92300 for Run keys or 92025/92028/92042/92069 under Sysmon event 1, absorb the events they match, so the
   library's rules hang under them as well as under the generic parent. Other siblings are tried highest level first.
3. **`if_sid` attaches a child to only the first copy of its parent; `if_group` attaches it to every copy.** A rule
   with several parents exists several times in the rule tree, so its own children use `if_group`.
4. **Group correlation stores an event once per copy of the matching rule.** A 5-event threshold over a rule with
   three parents fired after 2 events. Bursts therefore count one rule by ID (`if_matched_sid`) and attach with
   `if_group` (UC23-UC25), or pass through a single funnel rule (UC21).
5. **An event is stored either in the rule-ID history or in the group history, never both,** and an event that already
   triggered a correlation cannot trigger another one of the same or lower level. UC17's chains key on UC07's 110701
   and 110702, not on the level-15 110703.
6. **Correlation is per agent by default** (`same_agent` is deprecated). A Sysmon event and a FIM event from the same
   Windows host join without any shared field (UC25 112506).
7. **Group correlation is linked when the rule loads,** so a correlation rule only sees groups defined above it, and
   group names match as substrings. `tests/lint_rules.py` checks both.
8. **`frequency="N"` fires on the Nth matching event, then the counted events are consumed.** The next alert needs a
   fresh N events, which keeps a running bot from producing an alert storm (with `ignore` on top).
9. **No numeric comparison** exists in Wazuh 4.x rules, so "30% or more" or "0x10 bit set in an access mask" are
   regular expressions on the field (UC08, UC09, UC20). The default `osregex` type has no `(a|b)` grouping; those
   fields use `type="pcre2"`.
10. **Windows field names keep their spaces.** Wazuh only lower-cases the first letter, so Defender's `New Value`
    becomes `win.eventdata.new Value`, and paths arrive with doubled backslashes (regexes use `\\+`).
11. **Duplicate alerts are tuned out, not ignored.** Tuning rules 110021/110022 claim the nginx 401/403/404 lines for
    portal actions that the audit log already covers, and use `no_log`. Where Wazuh already has a rule for the same
    behaviour (certutil 92075/92018, LSASS 92900, SAM 92026, Set-MpPreference 92008-92015), the library rule is
    attached as its child, so one event still gives one alert, the more specific one.
12. **`wazuh-logtest` cannot replay EventChannel or FIM events.** Those cases run in the analysis engine built from
    source (`tests/lab-engine-report.md`) and are proven live in the lab.

13. **A duplicate rule ID is only a warning.** The manager logs warning 7612 and keeps the first copy, so a clash
    with rules already on the manager would silently disable part of the library. `deploy_manager.sh` checks every
    ID before it installs anything.
14. **A Windows agent only reads events created after it starts.** Restarting the agent in the middle of a test
    loses the events that happened while it was down.
15. **`ignore` only silences the rule that raised the alert.** While a burst rule is ignored, the event alerts as
    its parent, so an escalated child of a burst repeats once per batch (40 files copied to USB gives four 112305
    alerts, not one).
16. **The Wazuh agent looks like an attacker twice a day.** Its configuration assessment runs `net user`,
    `wmic useraccount`, `auditpol` and `secedit` as SYSTEM at start and every 12 hours. The discovery-burst rule
    (UC21) excludes that parent process; it was found live as a false positive.
17. **Turning Defender back on logs a change too.** Re-enabling real-time protection writes event 5013 with a
    "reverted" value. The first version of 111904 raised an alert for the fix as well as the attack.
18. **Plugging in a USB drive makes Defender read LSASS.** Wazuh's built-in 92900 raises that at level 12. Tuning
    rule 112009 recognises the Defender engine by path and keeps the real credential-dumping rules clean.
19. **`<field name="srcuser">` is rejected,** and a CDB lookup on `user` checks `srcuser` first. Static fields have
    their own tags.
20. **A correlation can hide events from a burst.** In real portal traffic every search is seen by the application
    and then by nginx. The nginx event ends as the correlation rule 110604 and is never counted by the burst rule
    110602, even though both share a group. Rule 110605 counts the correlated events instead (UC06).
21. **Windows event values are stored JSON-escaped.** Backslashes are doubled and a quote arrives as `\"`.
    PowerShell starts native programs with a quoted full path, so a pattern such as `vssadmin(\.exe)?\s+` matched
    from Command Prompt and missed from PowerShell. Patterns now allow an optional escaped quote after the
    program name (UC19, UC20, UC21, UC22, UC25).
