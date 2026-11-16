/* MOE console - Alerts and Logs: search the Wazuh indexer, with a histogram, facets, filters, triage and export. */
import { el, app, api, fmt, href, go, query, rangeFrom, rangeText, timeControl, pageHead, notice, errorNotice, empty,
         levelBadge, ucChip, busy, parseTs, dig, chip, describe } from "./core.js";
import { timeColumns, intervalMs } from "./charts.js";
import { openEvent, openRule, summaryOf, triageLabel } from "./details.js";

const SIMPLE = { agent: "Agent", agent_id: "Agent ID", rule: "Rule", tactic: "Tactic", technique: "Technique", group: "Group",
                 decoder: "Decoder", location: "Source", uc: "Use case", level: "Level at least", triage: "Triage" };
const FACET_KEY = { "agent.name": "agent", "rule.id": "rule", "rule.mitre.tactic": "tactic", "rule.groups": "group",
                    "decoder.name": "decoder", "location": "location" };
const FACET_TITLE = { "agent.name": "Agents", "rule.id": "Rules", "rule.mitre.tactic": "ATT&CK tactics", "rule.groups": "Rule groups",
                      "decoder.name": "Decoders", "location": "Sources" };

export function renderSearch(main, kind, params) {
  const isAlerts = kind === "alerts";
  const st = { q: params.get("q") || "", range: rangeFrom(params), ours: params.get("ours") === "1", f: params.getAll("f"),
               nf: params.getAll("nf"), sort: params.get("sort") === "asc" ? "asc" : "desc" };
  for (const k of Object.keys(SIMPLE)) st[k] = params.get(k) || "";
  if (st.range.range !== "custom") app.range = { range: st.range.range };

  const urlParams = (over) => {
    const p = { ...st, ...over };
    const out = { q: p.q, ours: p.ours ? "1" : "", f: p.f, nf: p.nf, sort: p.sort === "asc" ? "asc" : "" };
    for (const k of Object.keys(SIMPLE)) out[k] = p[k];
    return { ...out, ...p.range };
  };
  const navigate = (over) => go(kind, urlParams(over));

  // ---- header and filters
  const exportLink = el("a", { class: "btn", href: `/api/export?${query({ kind, ...urlParams({}), limit: 5000 })}`, download: "" }, "Export CSV");
  main.append(pageHead(isAlerts ? "Alerts" : "Logs",
    isAlerts ? "Every alert Wazuh raised, from our use cases and from its built-in rules." :
      "Every event the agents sent, including the ones that matched no rule. Use it to show the source log behind an alert.",
    exportLink));

  const input = el("input", { type: "search", class: "q", value: st.q, name: "q", autocomplete: "off", spellcheck: "false",
    "aria-label": isAlerts ? "Search alerts" : "Search logs",
    placeholder: isAlerts ? "Search: certutil, pilgrim0042, rule.id:111201, rule.level:>=12" : "Search: powershell, /var/log/auth.log, agent.name:Ubuntu" });
  const form = el("form", { class: "qform", role: "search", onsubmit: (e) => { e.preventDefault(); navigate({ q: input.value.trim() }); } },
    input, el("button", { type: "submit", class: "btn btn-primary" }, "Search"));
  const tips = el("details", { class: "tips" }, el("summary", {}, "Search tips"),
    el("ul", {},
      el("li", {}, "Plain words find text anywhere in the event, ignoring case: ", el("code", { text: "certutil" }), ", ",
        el("code", { text: "C:\\Users\\Public" }), ", ", el("code", { text: "pilgrim0042" }), "."),
      el("li", {}, "A field and a value: ", el("code", { text: "rule.id:111201" }), ", ", el("code", { text: "agent.name:Windows-10" }), ", ",
        el("code", { text: "rule.level:>=12" }), ", ", el("code", { text: "data.srcip:203.0.113.40" }), "."),
      el("li", {}, "Combine with and, or, not (any case) and brackets, as in Threat Hunting: ", el("code", { text: "rule.groups:syscheck AND NOT agent.name:Ubuntu" }), "."),
      el("li", {}, "Wildcards inside a field: ", el("code", { text: "data.win.eventdata.image:*powershell.exe" }), "."),
      el("li", {}, "In any event, click + or \u2212 next to a field to keep or drop events with that value.")));

  const filters = el("div", { class: "filters" },
    timeControl(st.range, (r) => { app.range = r.range === "custom" ? app.range : { range: r.range }; navigate({ range: r }); }));
  if (isAlerts) {
    const ours = el("input", { type: "checkbox", checked: st.ours ? "" : null, onchange: () => navigate({ ours: ours.checked }) });
    const level = el("select", { "aria-label": "Minimum level", onchange: () => navigate({ level: level.value }) },
      el("option", { value: "" }, "Any level"), el("option", { value: "7" }, "Medium and above (7+)"),
      el("option", { value: "12" }, "High and above (12+)"), el("option", { value: "15" }, "Critical only (15)"));
    level.value = st.level;
    const uc = el("select", { "aria-label": "Use case", onchange: () => navigate({ uc: uc.value }) },
      el("option", { value: "" }, "Any use case"), app.cat.usecases.map((u) => el("option", { value: String(u.n) }, `${u.key} ${u.title}`)));
    uc.value = st.uc;
    const triage = el("select", { "aria-label": "Triage", onchange: () => navigate({ triage: triage.value }) },
      el("option", { value: "" }, "Any triage state"), el("option", { value: "waiting" }, "Waiting for triage"),
      el("option", { value: "investigating" }, "Investigating"), el("option", { value: "closed" }, "Closed (any outcome)"),
      el("option", { value: "true_positive" }, "True positive"), el("option", { value: "false_positive" }, "False positive"),
      el("option", { value: "benign" }, "Expected activity"));
    triage.value = st.triage;
    filters.append(el("label", { class: "switch" }, ours, el("span", { text: "Only our 25 use cases" })), level, uc, triage);
  }
  main.append(filters, el("div", { class: "searchbar" }, form, tips));

  // active filter pills
  const pills = el("ul", { class: "pills", "aria-label": "Active filters" });
  const pill = (label, remove) => pills.append(el("li", {}, el("span", { text: label }),
    el("button", { type: "button", class: "pill-x", "aria-label": `Remove filter ${label}`, onclick: remove }, "\u00d7")));
  for (const k of Object.keys(SIMPLE)) {
    if (!st[k] || (isAlerts && (k === "level" || k === "uc" || k === "triage"))) continue;
    pill(`${SIMPLE[k]}: ${k === "uc" ? (app.ucByN.get(Number(st[k])) || {}).key || st[k] : st[k]}`, () => navigate({ [k]: "" }));
  }
  st.f.forEach((s, i) => pill(s.replace(":", " is "), () => navigate({ f: st.f.filter((_, j) => j !== i) })));
  st.nf.forEach((s, i) => pill(`not ${s.replace(":", " = ")}`, () => navigate({ nf: st.nf.filter((_, j) => j !== i) })));
  if (pills.children.length) main.append(pills);

  // ---- layout
  const facets = el("aside", { class: "facets", "aria-label": "Narrow the results" });
  const results = el("div", { class: "results" });
  main.append(el("div", { class: "search-layout" }, facets, results));
  const histCard = el("section", { class: "card hist-card", "aria-label": "Events over time" });
  const head = el("div", { class: "results-head" });
  const tableWrap = el("div", { class: "table-wrap" });
  const more = el("div", { class: "more" });
  results.append(histCard, head, tableWrap, more);

  const tbody = el("tbody");
  const cols = isAlerts ? ["Time", "Level", "What happened", "Agent", "Use case", "Triage"] : ["Time", "Agent", "Source", "Event", "Rule"];
  const sortBtn = el("button", { type: "button", class: "linklike", title: "Change the order",
    onclick: () => navigate({ sort: st.sort === "asc" ? "desc" : "asc" }) }, st.sort === "asc" ? "Time, oldest first" : "Time, newest first");
  tableWrap.append(el("table", { class: `data results-table results-${kind}` },
    el("thead", {}, el("tr", {}, cols.map((c, i) => el("th", { scope: "col", class: `c-${i}` }, i === 0 ? sortBtn : c)))), tbody));

  let page = 0, loaded = 0, total = 0, rowsById = new Map();
  const searchParams = () => ({ kind, ...urlParams({}), size: 50 });

  async function load(next) {
    busy(results, true);
    try {
      const data = await api("/api/search", { ...searchParams(), page: next ? page + 1 : 0 });
      if (next) page += 1; else page = 0;
      total = data.total;
      if (!next) {
        drawHist(data);
        drawFacets(data);
        drawHead(data);
        tbody.textContent = "";
        loaded = 0;
        rowsById = new Map();
      }
      for (const h of data.hits) tbody.append(row(h));
      loaded += data.hits.length;
      more.textContent = "";
      if (loaded < Math.min(total, 10000)) {
        more.append(el("button", { type: "button", class: "btn", onclick: () => load(true) }, `Show 50 more (${fmt.num(loaded)} of ${fmt.num(total)})`));
      } else if (total > 10000) {
        more.append(el("p", { class: "empty", text: "Only the first 10,000 can be listed. Narrow the search or the time range." }));
      }
      if (isAlerts) loadTriage(data.hits);
    } catch (e) {
      if (!next) { histCard.textContent = ""; facets.textContent = ""; head.textContent = ""; tbody.textContent = ""; }
      head.append(errorNotice(e));
    } finally {
      busy(results, false);
    }
  }

  function drawHead(data) {
    head.textContent = "";
    if (data.index_missing) {
      head.append(isAlerts ? notice("setup", "No Wazuh alert index was found in the indexer.") :
        notice("setup", "Raw logs are not archived yet. Wazuh keeps only events that match a rule unless archiving is turned on. On the Wazuh server, in the console folder of the package, run this once:",
          el("pre", { class: "cmd", text: "sudo bash install-console.sh --enable-logs" }),
          el("p", { text: "New events are searchable here from then on. It costs disk space: turn it off when you no longer need it with --disable-logs." })));
      return;
    }
    const what = isAlerts ? "alert" : "event";
    head.append(el("p", { class: "count" }, el("strong", { text: fmt.num(data.total) }),
      ` ${data.total === 1 ? what : what + "s"}${data.relation === "gte" ? " or more" : ""} in the ${rangeText(st.range)}`));
    const how = data.note ? data.note : data.mode === "contains" ? "Matched the words anywhere in the event, ignoring case."
      : data.mode === "lucene" ? "Read as a field query (Lucene syntax)." : "";
    if (how) head.append(el("p", { class: "how", text: how }));
    if (data.timed_out) head.append(el("p", { class: "how", text: "The indexer stopped early: the numbers may be incomplete." }));
  }

  function drawHist(data) {
    histCard.textContent = "";
    histCard.append(timeColumns(data.histogram, {
      stacked: isAlerts, interval: data.interval, height: 150, unit: isAlerts ? "alerts" : "events",
      label: isAlerts ? "Alerts over time by severity" : "Events over time",
      onPick: (b) => navigate({ range: { range: "custom", from: String(b.t), to: String(b.t + intervalMs(data.interval)) } }),
    }));
  }

  function drawFacets(data) {
    facets.textContent = "";
    for (const [field, rows] of Object.entries(data.facets || {})) {
      if (!rows.length) continue;
      const key = FACET_KEY[field];
      const list = el("ul", { class: "facet-list" }, rows.map((r) => el("li", {},
        el("button", { type: "button", class: "facet-row", onclick: () => navigate({ [key]: r.value }),
          title: field === "rule.id" ? `${r.value}: ${r.label}` : r.value },
          field === "rule.id" ? levelBadge(r.level) : null,
          el("span", { class: "facet-name" }, field === "rule.id" ? `${r.value} ${r.label}` : r.value),
          el("span", { class: "facet-n", text: fmt.compact(r.n) })))));
      facets.append(el("section", { class: "facet" }, el("h2", { text: FACET_TITLE[field] || field }), list));
    }
  }

  function row(h) {
    const d = h.doc;
    const r = d.rule || {};
    const when = parseTs(d.timestamp);
    const open = () => openEvent(h, { kind, range: st.range, onFilter: (field, value, include) => {
      if (include) navigate({ f: [...st.f, `${field}:${value}`] }); else navigate({ nf: [...st.nf, `${field}:${value}`] });
    } });
    let tr;
    if (isAlerts) {
      tr = el("tr", {},
        el("td", { class: "c-time", text: Number.isFinite(when) ? fmt.stamp(when) : "" }),
        el("td", { class: "c-level" }, levelBadge(r.level)),
        el("td", { class: "c-what" }, el("button", { type: "button", class: "rowlink", onclick: open }, describe(d) || summaryOf(d) || "Alert"),
          el("span", { class: "sub", text: `rule ${r.id}${d.location ? `  ${d.location}` : ""}` })),
        el("td", { class: "c-agent", text: dig(d, "agent.name") || "" }),
        el("td", { class: "c-uc" }, h.uc ? ucChip(h.uc) : null),
        el("td", { class: "c-tri" }));
      if (d.id) rowsById.set(d.id, tr);
    } else {
      tr = el("tr", {},
        el("td", { class: "c-time", text: Number.isFinite(when) ? fmt.stamp(when) : "" }),
        el("td", { class: "c-agent", text: dig(d, "agent.name") || "" }),
        el("td", { class: "c-src" }, el("span", { text: d.location || "" }), el("span", { class: "sub", text: dig(d, "decoder.name") || "" })),
        el("td", { class: "c-event" }, el("button", { type: "button", class: "rowlink rowlink-log", onclick: open }, summaryOf(d) || "(no text)")),
        el("td", { class: "c-rule" }, r.id !== undefined ? el("button", { type: "button", class: "chip chip-btn", onclick: () => openRule(String(r.id)) },
          levelBadge(r.level), ` ${r.id}`) : null));
    }
    tr.addEventListener("click", (e) => { if (!e.target.closest("button, a")) open(); });
    return tr;
  }

  async function loadTriage(hits) {
    const ids = hits.map((h) => h.doc.id).filter(Boolean);
    if (!ids.length) return;
    try {
      const t = await api("/api/triage", { ids: ids.join(",") });
      for (const [id, rec] of Object.entries(t.items || {})) paintTriage(id, rec.status);
    } catch (e) { /* triage is optional */ }
  }
  function paintTriage(id, status) {
    const tr = rowsById.get(id);
    if (!tr) return;
    const cell = tr.querySelector(".c-tri");
    cell.textContent = "";
    if (status && status !== "new") cell.append(el("span", { class: `tri-tag tri-${status}`, text: triageLabel(status) }));
  }
  const onTriage = (e) => paintTriage(e.detail.id, e.detail.status);
  document.addEventListener("moe:triage", onTriage);

  load(false);
  return () => document.removeEventListener("moe:triage", onTriage);
}
