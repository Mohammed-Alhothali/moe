[All use cases](../../README.md#the-use-cases) · Previous: [UC17](../UC17-sudo-privilege-escalation/README.md) · Next: [UC19](../UC19-defense-evasion/README.md)

# UC18: Persistence on the web server through cron

| | |
|---|---|
| **Tactic** | Persistence |
| **ATT&CK** | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Cron, [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell, [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer |
| **Runs on** | web01 terminal |
| **Top rule** | 111804 (level 13) |
| **Rules** | [`wazuh/rules/pp-180-uc18_cron_persistence_rules.xml`](../../wazuh/rules/pp-180-uc18_cron_persistence_rules.xml) |
| **Regression cases** | [`tests/cases/uc18.json`](../../tests/cases/uc18.json) |

## Why it matters

A cron job is the classic way to keep a foothold on a Linux web server: it re-downloads the web shell or opens a reverse shell every few minutes, even after the original file is cleaned up.

## Log source

| Source | Where it is collected | Decoder |
|---|---|---|
| File integrity monitoring (web01) | syscheck realtime + `report_changes` on `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/crontabs` | Built-in syscheck |

## Detection logic

- 111801 (8): a cron file was modified or deleted. 111802 (10): a new cron file was created.
- 111803 (12): the crontab of a web service account (`www-data`, `portal`, `nginx`, `nobody`) changed; these accounts should never have personal crontabs.
- 111804 (13): the change ADDS a job that downloads code or opens a shell (`curl`, `wget`, `nc`, `/dev/tcp`, `bash -i`, `python -c`, `base64 -d`, `| sh`, files run from `/tmp` or `/dev/shm`).

### Rules (4 alerting, 0 supporting)

| Rule | Level | Description | ATT&CK |
|---|---|---|---|
| 111801 | 8 | UC18 Scheduled job file changed on the web server: `$(file)` | T1053.003 |
| 111802 | 10 | UC18 New scheduled job file on the web server: `$(file)` | T1053.003 |
| 111803 | 12 | UC18 Crontab of a web service account changed: `$(file)` | T1053.003 |
| 111804 | 13 | UC18 Cron job added that downloads code or opens a shell: `$(file)` | T1053.003, T1105, T1059.004 |

<details>
<summary>Rule XML</summary>

```xml
<rule id="111801" level="8">
  <if_sid>550, 553</if_sid>
  <field name="file" type="pcre2">^/etc/crontab$|^/etc/cron\.(d|hourly|daily|weekly|monthly)/.+|^/var/spool/cron/crontabs/.+</field>
  <description>UC18 Scheduled job file changed on the web server: $(file)</description>
  <mitre>
    <id>T1053.003</id>
  </mitre>
  <group>pp_cron,pp_cron_change,</group>
</rule>

<rule id="111802" level="10">
  <if_sid>554</if_sid>
  <field name="file" type="pcre2">^/etc/cron\.(d|hourly|daily|weekly|monthly)/.+|^/var/spool/cron/crontabs/.+</field>
  <description>UC18 New scheduled job file on the web server: $(file)</description>
  <mitre>
    <id>T1053.003</id>
  </mitre>
  <group>pp_cron,pp_cron_change,</group>
</rule>

<rule id="111803" level="12">
  <if_sid>550, 553, 554</if_sid>
  <field name="file" type="pcre2">^/var/spool/cron/crontabs/(www-data|portal|nginx|nobody)$</field>
  <description>UC18 Crontab of a web service account changed: $(file)</description>
  <mitre>
    <id>T1053.003</id>
  </mitre>
  <group>pp_cron,pp_cron_change,</group>
</rule>

<rule id="111804" level="13">
  <if_group>pp_cron_change</if_group>
  <field name="changed_content" type="pcre2">(?m)^>\s*[^#\s].*(\b(curl|wget|nc|ncat|socat|telnet)\b|/dev/(tcp|udp)/|\bbash\s+-i\b|\bpython[23]?\s+-c\b|\bperl\s+-e\b|\bbase64\s+(-d|--decode)\b|\|\s*(ba|da|z)?sh\b|\s/(tmp|var/tmp|dev/shm)/)</field>
  <description>UC18 Cron job added that downloads code or opens a shell: $(file)</description>
  <mitre>
    <id>T1053.003</id>
    <id>T1105</id>
    <id>T1059.004</id>
  </mitre>
  <group>pp_cron,</group>
</rule>
```

</details>

## Example alerts

Real output from the Wazuh analysis engine, produced by replaying this use case's regression cases (taken from [`demo/sample-alerts.ndjson`](../../demo/sample-alerts.ndjson)).

**111802, level 10:** UC18 New scheduled job file on the web server: /etc/cron.d/pp-uc18-test

```
File '/etc/cron.d/pp-uc18-test' added
```

**111801, level 8:** UC18 Scheduled job file changed on the web server: /etc/crontab

```
File '/etc/crontab' modified
```

## How to test it live

Runs on: web01 terminal.

1. web01: `echo '*/30 * * * * /usr/bin/true' | sudo crontab -u www-data -` gives 111803.
2. web01: `(sudo crontab -u www-data -l; echo '*/30 * * * * /usr/bin/curl -s http://198.51.100.9/ping -o /dev/null') | sudo crontab -u www-data -` gives 111804. 198.51.100.9 is a documentation address, so the job reaches nothing.
3. Clean up: `sudo crontab -u www-data -r`.

The full lab procedure is in [`docs/live-test-runbook.md`](../../docs/live-test-runbook.md).

## False-positive control

- Only ADDED, non-comment lines are inspected: a commented-out downloader stays at 111801 (case UC18-06).
- Package updates to `/etc/cron.daily` produce 111801/111802 at medium level; patch windows explain them.

## Regression cases

6 cases (5 positive, 1 negative) in [`tests/cases/uc18.json`](../../tests/cases/uc18.json), all passing in the [engine report](../../tests/lab-engine-report.md).

| Case | Kind | What it checks |
|---|---|---|
| UC18-01 | positive | /etc/crontab edited -> 111801 |
| UC18-02 | positive | New file in /etc/cron.d -> 111802 |
| UC18-03 | positive | Crontab created for www-data -> 111803 |
| UC18-04 | positive | cron.d job that downloads with curl -> 111804 |
| UC18-05 | positive | www-data crontab gets a reverse-shell style job -> 111804 |
| UC18-06 | negative | Downloader line that is commented out stays at 111801 (FP control) |

## How to improve it

- Correlate a new service-account crontab with a UC07 web-shell alert for a level-15 chain.
- Add systemd timers (`/etc/systemd/system/*.timer`) to the FIM paths.

---

_Rifadah Pilgrim Services is a fictional organisation. Every name, account, address and document in these examples is synthetic._
