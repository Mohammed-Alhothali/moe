/* MOE console - Agents: live status from the Wazuh server API, alert statistics from the indexer, one page per agent. */
import { el, app, api, fmt, href, go, rangeFrom, rangeText, timeControl, pageHead, card, errorNotice, notice, empty,
         levelBadge, ucChip, busy, parseTs, dig } from "./core.js";
import { timeColumns, rankBars, meter, intervalMs } from "./charts.js";
import { openEvent } from "./details.js";

const STATUS = { active: "Active", disconnected: "Disconnected", never_connected: "Never connected", pending: "Pending" };
const osName = (a) => [dig(a, "os.name"), dig(a, "os.version")].filter(Boolean).join(" ");
const keepAlive = (a) => {
  const t = parseTs(a.lastKeepAlive);
  if (!Number.isFinite(t) || String(a.lastKeepAlive).startsWith("9999")) return a.id === "000" ? "this server" : "";
  return fmt.ago(t);
};

export function renderAgents(main, params) {
  const range = rangeFrom(params);
  if (range.range !== "custom") app.range = { range: range.range };
  main.append(pageHead("Agents", "Every machine that reports to Wazuh, whether it is connected, and what it raised."));
  main.append(el("div", { class: "filters" }, timeControl(range, (r) => go("agents", r))));
  const body = el("div", {});
  main.append(body);
  busy(body, true);
  (async () => {
    let d;
    try { d = await api("/api/agents", range); } catch (e) { body.append(errorNotice(e)); busy(body, false); return; }
    busy(body, false);
    for (const n of d.notes) body.append(notice("setup", n));
    if (d.summary) {
      const s = d.summary;
      body.append(el("div", { class: "tiles tiles-small" },
        mini("Active", s.active, "ok"), mini("Disconnected", s.disconnected, s.disconnected ? "bad" : "ok"),
        mini("Never connected", s.never_connected, s.never_connected ? "warn" : "ok"), mini("Total", s.total, "")));
    }
    const rows = d.agents.map((a) => ({ a, s: d.stats[String(a.id)] || {} }));
    body.append(el("div", { class: "table-wrap" }, el("table", { class: "data agents-table" },
      el("caption", { class: "sr-only", text: `Agents and their alerts in the ${rangeText(range)}` }),
      el("thead", {}, el("tr", {}, ["Status", "Agent", "Address", "Operating system", "Wazuh", "Last seen", "Alerts", "High+", "Use-case alerts", "Top level"]
        .map((c, i) => el("th", { scope: "col", class: i >= 6 && i <= 8 ? "num" : "" }, c)))),
      el("tbody", {}, rows.map(({ a, s }) => {
        const status = a.status || (s.last ? "seen" : "unknown");
        const tr = el("tr", { class: "clickable" },
          el("td", {}, el("span", { class: `status st-${status}` }, el("span", { class: "dot", "aria-hidden": "true" }), STATUS[status] || (status === "seen" ? "Seen in alerts" : "Unknown"))),
          el("td", {}, el("a", { href: href(`agents/${a.id}`, range), class: "strong" }, a.id === "000" ? `${a.name} (Wazuh server)` : a.name || a.id),
            el("span", { class: "sub", text: `ID ${a.id}${a.group ? `  groups: ${[].concat(a.group).join(", ")}` : ""}` })),
          el("td", { text: a.ip || "" }),
          el("td", { text: osName(a) }),
          el("td", { text: (a.version || "").replace(/^Wazuh /, "") }),
          el("td", { text: a.status ? keepAlive(a) : s.last ? fmt.ago(s.last) : "" }),
          el("td", { class: "num", text: fmt.num(s.alerts || 0) }),
          el("td", { class: "num", text: fmt.num(s.high || 0) }),
          el("td", { class: "num", text: fmt.num(s.ours || 0) }),
          el("td", {}, s.level ? levelBadge(s.level) : ""));
        tr.addEventListener("click", (e) => { if (!e.target.closest("a")) go(`agents/${a.id}`, range); });
        return tr;
      })))));
    if (d.source !== "api") body.append(el("p", { class: "fine", text: "Live connection status needs the Wazuh server API; this list comes from agents seen in alerts." }));
  })();
}

function mini(label, value, state) {
  return el("div", { class: `tile tile-mini${state ? " t-" + state : ""}` }, el("span", { class: "tile-label", text: label }),
    el("span", { class: "tile-value", text: fmt.num(value || 0) }));
}

export function renderAgent(main, id, params) {
  const range = rangeFrom(params);
  main.append(el("p", { class: "crumbs" }, el("a", { href: href("agents", range) }, "Agents"), ` / ${id}`));
  const head = el("div", {});
  main.append(head, el("div", { class: "filters" }, timeControl(range, (r) => go(`agents/${id}`, r))));
  const body = el("div", { class: "agent-page" });
  main.append(body);
  busy(body, true);
  (async () => {
    let d;
    try { d = await api("/api/agent", { id, ...range }); } catch (e) { body.append(errorNotice(e)); busy(body, false); return; }
    busy(body, false);
    const a = d.agent || {};
    const name = a.name || (d.latest && d.latest[0] && dig(d.latest[0].doc, "agent.name")) || `Agent ${id}`;
    head.append(el("div", { class: "page-head" },
      el("div", { class: "page-title" }, el("h1", { text: id === "000" ? `${name} (Wazuh server)` : name }),
        el("p", { class: "lede lede-row" },
          a.status ? el("span", { class: `status st-${a.status}` }, el("span", { class: "dot", "aria-hidden": "true" }), STATUS[a.status] || a.status) : null,
          el("span", { text: `ID ${id}` }), a.ip ? el("span", { text: a.ip }) : null, osName(a) ? el("span", { text: osName(a) }) : null,
          a.version ? el("span", { text: a.version }) : null)),
      el("div", { class: "page-side" },
        el("a", { class: "btn", href: href("alerts", { agent_id: id, ...range }) }, "This agent's alerts"),
        el("a", { class: "btn", href: href("logs", { agent_id: id, ...range }) }, "This agent's logs"))));
    for (const n of d.notes) body.append(notice("setup", n));

    body.append(card(`Alerts in the ${rangeText(range)}: ${fmt.num(d.total || 0)}`, { class: "span-all" },
      d.histogram ? timeColumns(d.histogram, { stacked: true, interval: d.interval, height: 160, label: "This agent's alerts over time",
        onPick: (b) => go("alerts", { agent_id: id, range: "custom", from: String(b.t), to: String(b.t + intervalMs(d.interval)) }) }) : empty("No alert data.")));

    const ucs = (d.usecases || []).sort((x, y) => y.level - x.level);
    body.append(el("div", { class: "grid2" },
      card("Top rules", {}, rankBars((d.rules || []).map((r) => ({ label: `${r.id} ${r.label}`, value: r.n, title: `Rule ${r.id}: ${r.label}`,
        href: href("alerts", { agent_id: id, rule: r.id, ...range }), lead: levelBadge(r.level) })))),
      card("Our use cases on this agent", {}, ucs.length ? el("ul", { class: "ucfired" }, ucs.map((s) => el("li", {}, ucChip(s.n),
        el("span", { class: "ucf-text", text: (app.ucByN.get(s.n) || {}).title || "" }), levelBadge(s.level), el("span", { class: "ucf-n", text: fmt.num(s.hits) }))))
        : empty("None of the 25 use cases fired here in this time range."))));

    body.append(el("div", { class: "grid2" },
      card("Recent file changes", {}, (d.fim || []).length ? el("ol", { class: "feedlist" }, d.fim.map((h) => {
        const sc = h.doc.syscheck || {};
        return el("li", {}, el("button", { type: "button", class: "feedrow", onclick: () => openEvent(h, { range }) },
          levelBadge(dig(h.doc, "rule.level")), el("span", { class: "feed-what" }, el("span", { class: "feed-desc mono-path", text: sc.path || "" }),
            el("span", { class: "sub", text: `${sc.event || "changed"}  ${fmt.stamp(parseTs(h.doc.timestamp))}  rule ${dig(h.doc, "rule.id")}` }))));
      })) : empty("No file integrity alerts in this time range.")),
      card("Configuration assessment (SCA)", {}, scaBlock(d.sca))));

    body.append(el("div", { class: "grid2" },
      card("Vulnerabilities", {}, vulnBlock(d.vulnerabilities)),
      card("System", {}, sysBlock(a, d.os, d.hardware))));
  })();
}

function scaBlock(sca) {
  if (sca === null) return empty("Needs the Wazuh server API connection.");
  if (!sca.length) return empty("No SCA scan results for this agent yet.");
  return el("ul", { class: "sca" }, sca.map((p) => el("li", {},
    el("p", { class: "sca-name", text: p.name || p.policy_id }),
    el("div", { class: "sca-row" }, meter(p.score || 0, 100, `${p.name}: score ${p.score}%`), el("span", { class: "sca-score", text: `${p.score ?? "?"}%` })),
    el("p", { class: "sub", text: `${fmt.num(p.pass)} passed, ${fmt.num(p.fail)} failed${p.invalid ? `, ${fmt.num(p.invalid)} not applicable` : ""}${p.end_scan ? `. Last scan ${fmt.ago(parseTs(p.end_scan))}` : ""}` }))));
}

function vulnBlock(v) {
  if (!v) return empty("No vulnerability data (the vulnerability detector is off, or has not scanned this agent).");
  const order = ["Critical", "High", "Medium", "Low"];
  return el("div", {},
    el("ul", { class: "vsev" }, order.map((s) => el("li", { class: `vs vs-${s.toLowerCase()}` }, el("span", { class: "vs-n", text: fmt.num(v.severity[s] || 0) }), el("span", { text: s })))),
    v.top.length ? el("table", { class: "data compact" },
      el("thead", {}, el("tr", {}, ["CVE", "Severity", "Score", "Package"].map((c) => el("th", { scope: "col", text: c })))),
      el("tbody", {}, v.top.map((x) => el("tr", {}, el("td", { text: dig(x, "vulnerability.id") || "" }), el("td", { text: dig(x, "vulnerability.severity") || "" }),
        el("td", { text: String(dig(x, "vulnerability.score.base") ?? "") }), el("td", { text: `${dig(x, "package.name") || ""} ${dig(x, "package.version") || ""}` }))))) : null);
}

function sysBlock(a, os, hw) {
  const rows = [];
  const add = (k, v) => { if (v) rows.push(el("dt", { text: k }), el("dd", { text: String(v) })); };
  add("Name", a.name); add("Address", a.ip); add("Operating system", os ? [dig(os, "os.name"), dig(os, "os.version")].filter(Boolean).join(" ") : osName(a));
  add("Architecture", os && os.architecture); add("Processor", hw && dig(hw, "cpu.name")); add("Cores", hw && dig(hw, "cpu.cores"));
  add("Memory", hw && dig(hw, "ram.total") ? `${(dig(hw, "ram.total") / 1048576).toFixed(1)} GB, ${dig(hw, "ram.usage")}% used` : "");
  add("Wazuh agent", a.version); add("Registered", a.dateAdd ? new Date(parseTs(a.dateAdd)).toLocaleDateString() : "");
  add("Groups", a.group ? [].concat(a.group).join(", ") : "");
  return rows.length ? el("dl", { class: "kv" }, rows) : empty("Needs the Wazuh server API connection.");
}
