/* MOE console - detail drawers: one alert or event (with triage), one rule (its XML), one ATT&CK technique. */
import { el, app, api, post, fmt, dig, flatten, levelBadge, levelName, ucChip, href, go, openDrawer, closeDrawer,
         parseTs, copyText, toast, errorNotice, chip, rangeText, describe, readable } from "./core.js";

export const TRIAGE = [
  { key: "new", label: "New" }, { key: "investigating", label: "Investigating" },
  { key: "true_positive", label: "True positive" }, { key: "false_positive", label: "False positive" },
  { key: "benign", label: "Expected activity" }];
export const triageLabel = (k) => (TRIAGE.find((t) => t.key === k) || TRIAGE[0]).label;

function section(title, ...content) {
  return el("section", { class: "d-section" }, el("h3", { text: title }), ...content);
}

/* ---------------- XML, coloured by token, built from text nodes only ---------------- */
export function xmlView(text) {
  const pre = el("pre", { class: "xml", tabindex: "0" });
  const s = String(text || "");
  let i = 0;
  const add = (cls, t) => { if (t) pre.append(cls ? el("span", { class: cls, text: t }) : document.createTextNode(t)); };
  while (i < s.length) {
    if (s.startsWith("<!--", i)) {
      const end = s.indexOf("-->", i);
      const stop = end < 0 ? s.length : end + 3;
      add("x-com", s.slice(i, stop)); i = stop; continue;
    }
    if (s[i] === "<") {
      let j = i + 1, quote = null;
      while (j < s.length && (quote || s[j] !== ">")) { if (s[j] === '"' || s[j] === "'") quote = quote === s[j] ? null : quote || s[j]; j++; }
      const tag = s.slice(i, Math.min(s.length, j + 1));
      const m = tag.match(/^(<\/?)([\w:.-]*)([\s\S]*?)(\/?>)?$/);
      if (m) {
        add("x-punc", m[1]); add("x-tag", m[2]);
        const attrs = m[3];
        let k = 0;
        const re = /([\w:.-]+)(\s*=\s*)("[^"]*"|'[^']*')|(\s+)|([\s\S])/g;
        let a;
        while ((a = re.exec(attrs))) {
          if (a[1]) { add("x-attr", a[1]); add("x-punc", a[2]); add("x-val", a[3]); }
          else add(null, a[0]);
          k = re.lastIndex;
        }
        add("x-punc", m[4] || "");
      } else add(null, tag);
      i = j + 1; continue;
    }
    const next = s.indexOf("<", i);
    const stop = next < 0 ? s.length : next;
    add("x-text", s.slice(i, stop)); i = stop;
  }
  return pre;
}

/* ---------------- one alert / event ---------------- */
const HIDE = /^(data\.win\.system\.(providerGuid|eventRecordID|processID|threadID|keywords|task|opcode|version|severityValue)|manager\.name|decoder\.(parent|ftscomment)|rule\.(firedtimes|mail)|input\.type|cluster\.\w+|@timestamp|@version)$/;
const NO_FILTER = /^(full_log|previous_output|previous_log|syscheck\.diff|data\.win\.system\.message|timestamp)$/;

export function openEvent(item, opts) {
  opts = opts || {};
  const doc = item.doc || item.alert || {};
  const r = doc.rule || {};
  const uc = item.uc ? app.ucByN.get(item.uc) : null;
  const isAlert = r.id !== undefined && opts.kind !== "logs";
  openDrawer((body) => {
    const when = parseTs(doc.timestamp);
    const agent = doc.agent || {};
    body.append(el("div", { class: "d-chips" },
      uc ? ucChip(uc.n) : null,
      r.id !== undefined ? el("button", { type: "button", class: "chip chip-btn", onclick: () => openRule(String(r.id)) }, `Rule ${r.id}`) : null,
      r.level !== undefined ? el("span", { class: "chip" }, levelBadge(r.level), ` ${levelName(r.level)}`) : null));
    body.append(el("h2", { class: "d-title", id: "drawer-title", text: describe(doc) || summaryOf(doc) || "Event" }));
    body.append(el("p", { class: "d-meta" },
      Number.isFinite(when) ? `${new Date(when).toLocaleString()} ` : "",
      agent.name ? el("span", {}, "on ", agent.id ? el("a", { href: href(`agents/${agent.id}`), onclick: closeDrawer }, agent.name) : agent.name,
        agent.ip ? ` (${agent.ip})` : "") : null,
      doc.location ? el("span", { class: "d-loc" }, ` from ${doc.location}`) : null));
    const actions = el("div", { class: "actions" });
    if (r.id !== undefined) {
      actions.append(el("button", { type: "button", class: "btn", onclick: () => openRule(String(r.id)) }, "Show the rule"));
      actions.append(el("a", { class: "btn", href: href("alerts", { rule: r.id, ...(opts.range || app.range) }), onclick: closeDrawer },
        "All alerts from this rule"));
    }
    if (uc) actions.append(el("a", { class: "btn", href: href(`usecases/${uc.key}`), onclick: closeDrawer }, `Open ${uc.key}`));
    const copy = el("button", { type: "button", class: "btn", onclick: () => copyText(JSON.stringify(doc, null, 2), copy, "Copy JSON") }, "Copy JSON");
    actions.append(copy);
    body.append(actions);

    if (isAlert && doc.id) body.append(triageBox(doc));

    const mitre = dig(doc, "rule.mitre.id") || [];
    if (mitre.length) {
      body.append(section("ATT&CK", el("ul", { class: "d-tech" }, mitre.map((t, k) =>
        el("li", {}, el("a", { href: href("attack", { t }), onclick: closeDrawer }, t), " ",
          (app.cat.techniques[t] || {}).name || (dig(doc, "rule.mitre.technique") || [])[k] || "")))));
    }
    if (doc.full_log) body.append(section(isAlert ? "Original event" : "Event", el("pre", { class: "d-log", text: doc.full_log })));
    if (doc.syscheck && doc.syscheck.diff) body.append(section("What changed in the file", el("pre", { class: "d-log", text: doc.syscheck.diff })));

    const fields = flatten(doc).filter(([k]) => !HIDE.test(k) && k !== "full_log" && !k.startsWith("syscheck.diff"));
    const order = (k) => (k.startsWith("rule.") ? 0 : k.startsWith("agent.") ? 1 : k.startsWith("data.") ? 2 : k.startsWith("syscheck.") ? 3 : 4);
    fields.sort((a, b) => order(a[0]) - order(b[0]) || a[0].localeCompare(b[0]));
    const dl = el("dl", { class: "d-fields" });
    for (const [k, v] of fields.slice(0, 160)) {
      const dd = el("dd", {}, el("span", { class: "fv", text: v }));
      if (opts.onFilter && !NO_FILTER.test(k) && v.length <= 1000 && !v.includes(", ")) {
        dd.append(el("span", { class: "fbtns" },
          el("button", { type: "button", class: "fbtn", title: `Show only ${k} = ${v}`, "aria-label": `Filter for ${k} ${v}`,
            onclick: () => { closeDrawer(); opts.onFilter(k, v, true); } }, "+"),
          el("button", { type: "button", class: "fbtn", title: `Hide ${k} = ${v}`, "aria-label": `Filter out ${k} ${v}`,
            onclick: () => { closeDrawer(); opts.onFilter(k, v, false); } }, "−")));
      }
      dl.append(el("dt", { text: k }), dd);
    }
    body.append(section("Fields", opts.onFilter ? el("p", { class: "d-hint", text: "Use + to show only matching events, − to hide them." }) : null, dl));
    body.append(el("details", { class: "d-raw" }, el("summary", {}, "Raw JSON"), el("pre", { class: "d-log", text: JSON.stringify(doc, null, 2) })));
  });
}

const SYSMON = { 1: "Process started", 3: "Network connection", 7: "Image loaded", 8: "Remote thread created", 10: "Process accessed",
  11: "File created", 12: "Registry key created or deleted", 13: "Registry value set", 17: "Pipe created", 18: "Pipe connected",
  22: "DNS query", 23: "File deleted", 26: "File deleted" };
const WINEV = { 4624: "Logon", 4625: "Failed logon", 4634: "Logoff", 4648: "Logon with explicit credentials", 4672: "Admin logon",
  4688: "Process started", 4698: "Scheduled task created", 4719: "Audit policy changed", 4720: "Account created",
  4726: "Account deleted", 4728: "Added to a global group", 4732: "Added to a local group", 4740: "Account locked out",
  7045: "Service installed", 1102: "Security log cleared", 104: "Event log cleared", 4104: "PowerShell script block",
  5001: "Defender real-time protection off", 5007: "Defender setting changed", 5013: "Defender tamper protection blocked a change",
  1116: "Defender detected malware", 6416: "New external device" };

/* A one-line, readable version of any event, for tables and lists. Windows values arrive with doubled backslashes. */
export function summaryOf(doc) {
  const w = dig(doc, "data.win");
  if (w) {
    const ev = Number(dig(w, "system.eventID"));
    const sysmon = /sysmon/i.test(String(dig(w, "system.channel") || dig(w, "system.providerName") || ""));
    const name = (sysmon ? SYSMON[ev] : WINEV[ev]) || `Event ${ev || "?"}`;
    const e = w.eventdata || {};
    const what = e.commandLine || e.queryName || e.targetFilename || e.targetObject || e.imagePath || e.image ||
      e.targetUserName || dig(w, "system.message") || "";
    return `${sysmon ? "Sysmon" : "Windows"} ${ev || ""} ${name}: ${readable(what, true).slice(0, 220)}`.trim();
  }
  if (doc.full_log) return String(doc.full_log).slice(0, 260);
  if (doc.syscheck) return `File ${doc.syscheck.event || "changed"}: ${doc.syscheck.path || ""}`;
  const sca = dig(doc, "data.sca");
  if (sca) {
    const check = sca.check || {};
    return `SCA ${check.title ? `check ${check.id || ""} ${check.title}: ${check.result || ""}` : `${sca.policy || ""} ${sca.type || ""}`}`.replace(/\s+/g, " ").trim();
  }
  const vuln = dig(doc, "data.vulnerability");
  if (vuln) return `Vulnerability ${vuln.cve || vuln.id || ""} in ${dig(vuln, "package.name") || "a package"}`;
  // anything else: the rule that matched it, or its first decoded fields
  if (dig(doc, "rule.description")) return readable(doc.rule.description);
  return flatten(doc.data || {}).slice(0, 4).map(([k, v]) => `${k}=${v}`).join("  ").slice(0, 260);
}

function triageBox(doc) {
  const box = el("section", { class: "d-section triage", "aria-label": "Triage" }, el("h3", { text: "Triage" }));
  const status = el("div", { class: "triage-status", role: "radiogroup", "aria-label": "Status" });
  const note = el("textarea", { rows: "3", maxlength: "2000", placeholder: "What did you check, and what did you find?", "aria-label": "Triage note" });
  const save = el("button", { type: "button", class: "btn btn-primary" }, "Save triage");
  const hist = el("ol", { class: "triage-history" });
  let current = "new";
  const paint = () => status.querySelectorAll("button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.k === current)));
  for (const t of TRIAGE) {
    status.append(el("button", { type: "button", role: "radio", "data-k": t.key, class: `tri tri-${t.key}`,
      onclick: () => { current = t.key; paint(); } }, t.label));
  }
  paint();
  save.addEventListener("click", async () => {
    save.disabled = true;
    try {
      await post("/api/triage", { id: doc.id, status: current, note: note.value, rule: dig(doc, "rule.id"),
        level: dig(doc, "rule.level"), agent: dig(doc, "agent.name"), description: dig(doc, "rule.description"),
        alert_time: doc.timestamp });
      toast(`Saved: ${triageLabel(current)}`);
      document.dispatchEvent(new CustomEvent("moe:triage", { detail: { id: doc.id, status: current } }));
      loadHistory();
    } catch (e) {
      toast(e.message);
    } finally { save.disabled = false; }
  });
  async function loadHistory() {
    try {
      const h = await api("/api/triage/history", { id: doc.id });
      hist.textContent = "";
      if (h.history.length) {
        current = h.history[0].status; paint();
        if (!note.value) note.value = h.history[0].note || "";
      }
      for (const row of h.history) {
        hist.append(el("li", {}, el("strong", { text: triageLabel(row.status) }),
          ` by ${row.by || "?"}, ${new Date(row.at * 1000).toLocaleString()}`, row.note ? el("span", { class: "tri-note", text: row.note }) : null));
      }
    } catch (e) { /* history is optional */ }
  }
  loadHistory();
  box.append(status, note, el("div", { class: "actions" }, save), hist);
  return box;
}

/* ---------------- one rule ---------------- */
export async function openRule(id) {
  openDrawer((body) => {
    body.append(el("p", { class: "d-key", text: `Rule ${id}` }), el("p", { class: "d-quiet", text: "Loading the rule..." }));
  }, { wide: true });
  let r;
  try { r = await api("/api/rule", { id }); } catch (e) {
    return openDrawer((body) => body.append(el("p", { class: "d-key", text: `Rule ${id}` }), errorNotice(e)), { wide: true });
  }
  openDrawer((body) => {
    const xml = r.entries.length ? r.entries[0].xml : "";
    const level = (xml.match(/level\s*=\s*["'](\d+)["']/) || [])[1];
    const desc = (xml.match(/<description>([\s\S]*?)<\/description>/) || [])[1];
    body.append(el("div", { class: "d-chips" }, r.uc ? ucChip(r.uc) : null, level !== undefined ? el("span", { class: "chip" }, levelBadge(level), ` ${levelName(level)}`) : null),
      el("h2", { class: "d-title", id: "drawer-title" }, `Rule ${id}`),
      desc ? el("p", { class: "d-lede", text: desc.replace(/\s+/g, " ").trim() }) : null);
    if (!r.entries.length) { body.append(el("p", { class: "notice notice-setup" }, r.error || "Rule not found.")); return; }
    body.append(el("p", { class: "d-meta" }, r.source === "server" ? "Read from the Wazuh server: " : "From the detection library: ",
      el("code", { text: r.entries[0].file })));
    const ruleChips = (list) => list.map((p) => el("button", { type: "button", class: "chip chip-btn", onclick: () => openRule(p) }, `Rule ${p}`));
    if (r.parents.length || r.groups.length) {
      body.append(section("Checked only after",
        el("p", { class: "d-hint", text: "This rule is only tried on an event that one of these rules or groups already matched." }),
        el("div", { class: "d-chips" }, ruleChips(r.parents), r.groups.map((g) => chip(`group ${g}`)))));
    }
    if ((r.matched || []).length || (r.matched_groups || []).length) {
      const freq = (xml.match(/frequency\s*=\s*["'](\d+)["']/) || [])[1];
      const tf = (xml.match(/timeframe\s*=\s*["'](\d+)["']/) || [])[1];
      body.append(section("Correlates with earlier events",
        el("p", { class: "d-hint", text: freq ? `Fires when ${freq} events from these arrive within ${tf || "?"} seconds.`
          : `Fires only if one of these matched an earlier event in the last ${tf || "?"} seconds.` }),
        el("div", { class: "d-chips" }, ruleChips(r.matched || []), (r.matched_groups || []).map((g) => chip(`group ${g}`)))));
    }
    if (r.lists.length) {
      body.append(section("Lists it looks up", el("ul", { class: "d-plain" }, r.lists.map((l) => {
        const name = l.split("/").pop();
        const rows = app.cat.lists[name];
        return el("li", {}, el("code", { text: l }), rows ? el("pre", { class: "d-log d-list", text: rows.join("\n") }) : null);
      }))));
    }
    body.append(section("Rule XML", xmlView(xml)));
    if (r.entries.length > 1) {
      body.append(section("Also defined in", el("ul", { class: "d-plain" }, r.entries.slice(1).map((e) => el("li", {}, el("code", { text: e.file }))))));
    }
    body.append(el("div", { class: "actions" },
      el("a", { class: "btn", href: href("alerts", { rule: id, ...app.range }), onclick: closeDrawer }, "Alerts from this rule"),
      el("button", { type: "button", class: "btn", onclick: (e) => copyText(xml, e.currentTarget, "Copy XML") }, "Copy XML")));
  }, { wide: true });
}

/* ---------------- one ATT&CK technique ---------------- */
export function openTechnique(tid, stats, range) {
  const t = app.cat.techniques[tid] || {};
  const name = t.name || (stats && stats.name) || "";
  const ucs = app.cat.usecases.filter((u) => u.techniques.includes(tid));
  openDrawer((body) => {
    body.append(el("p", { class: "d-key", text: tid }), el("h2", { class: "d-title", id: "drawer-title", text: name || tid }),
      el("p", { class: "d-meta", text: (t.tactics || (stats && stats.tactics) || []).join(", ") }));
    body.append(section("Alerts", el("p", {},
      `${fmt.num(stats ? stats.all : 0)} alerts carried this technique in the ${rangeText(range)}`,
      stats && stats.ours ? `, ${fmt.num(stats.ours)} of them from our use cases.` : ".")));
    if (ucs.length) {
      body.append(section("Detected by our use cases", el("ul", { class: "d-plain" }, ucs.map((u) => el("li", {},
        ucChip(u.n), " ", u.title, el("ul", { class: "d-rules-inline" }, u.rules.filter((r) => (r.mitre || []).includes(tid)).map((r) =>
          el("li", {}, el("button", { type: "button", class: "linklike", onclick: () => openRule(r.id) }, `Rule ${r.id}`), ` level ${r.level}: ${r.description}`))))))));
    } else {
      body.append(section("Detected by", el("p", { text: "Built-in Wazuh rules only. None of our 25 use cases covers this technique yet." })));
    }
    body.append(el("div", { class: "actions" },
      el("a", { class: "btn btn-primary", href: href("alerts", { technique: tid, ...range }), onclick: closeDrawer }, "Search these alerts"),
      el("a", { class: "btn", href: `https://attack.mitre.org/techniques/${tid.replace(".", "/")}/`, target: "_blank", rel: "noopener noreferrer" }, "MITRE page")));
  });
}

export { go };
