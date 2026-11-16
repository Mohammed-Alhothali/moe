/* MOE console - Overview: what happened across every agent in the chosen time, and whether the pipeline is healthy. */
import { el, app, api, fmt, href, go, rangeFrom, rangeText, timeControl, pageHead, card, errorNotice, empty, levelBadge,
         ucChip, busy, parseTs, dig, describe } from "./core.js";
import { timeColumns, rankBars, severitySplit, intervalMs } from "./charts.js";
import { openEvent } from "./details.js";

export function renderOverview(main, params) {
  const range = rangeFrom(params);
  if (range.range !== "custom") app.range = { range: range.range };
  main.append(pageHead("Overview", "Everything Wazuh saw on every agent, with our 25 use cases picked out."));
  main.append(el("div", { class: "filters" }, timeControl(range, (r) => go("overview", r))));
  const body = el("div", { class: "overview" });
  main.append(body);
  busy(body, true);
  let alive = true;
  load();
  const timer = setInterval(() => { if (alive && document.visibilityState === "visible") load(true); }, 30000);
  return () => { alive = false; clearInterval(timer); };

  async function load(quiet) {
    if (!quiet) busy(body, true);
    let d;
    try { d = await api("/api/overview", range); } catch (e) {
      body.textContent = ""; body.append(errorNotice(e)); busy(body, false); return;
    }
    if (!alive) return;
    body.textContent = "";
    busy(body, false);
    const high = (d.levels.high || 0) + (d.levels.crit || 0);
    const fired = d.ours.usecases.length;
    body.append(el("div", { class: "tiles" },
      tile("Alerts", fmt.num(d.total), `in the ${rangeText(range)}`, href("alerts", range)),
      tile("High and critical", fmt.num(high), `level 12 and above`, href("alerts", { level: 12, ...range })),
      tile("Use-case alerts", fmt.num(d.ours.total), `${fired} of ${app.cat.usecases.length} use cases fired`, href("alerts", { ours: 1, ...range })),
      tile("Waiting for triage", fmt.num(d.triage.untriaged), d.triage.high_in_window ? `of ${fmt.plural(d.triage.high_in_window, "high alert")}` : "no high alerts",
        href("alerts", { level: 12, triage: "waiting", ...range }))));

    body.append(card("Alerts over time", { class: "span-all", side: el("div", { class: "card-side" }, severitySplit(d.levels, d.total)) },
      timeColumns(d.histogram, { stacked: true, interval: d.interval, height: 200, label: "Alerts over time by severity",
        onPick: (b) => go("alerts", { range: "custom", from: String(b.t), to: String(b.t + intervalMs(d.interval)) }) })));

    body.append(el("div", { class: "grid3" },
      card("Top rules", {}, rankBars(d.rules.map((r) => ({
        label: `${r.id} ${r.label}`, value: r.n, href: href("alerts", { rule: r.id, ...range }), title: `Rule ${r.id}: ${r.label}`,
        lead: el("span", { class: "rank-lead" }, levelBadge(r.level), r.uc ? el("span", { class: "uc-mini", text: (app.ucByN.get(r.uc) || {}).key }) : null),
      })), { unit: "alerts" })),
      card("Agents", {}, rankBars(d.agents.map((a) => ({ label: a.name, value: a.n, href: href("alerts", { agent: a.name, ...range }),
        lead: levelBadge(a.level) })), { unit: "alerts" })),
      card("ATT&CK tactics", {}, rankBars(d.tactics.map((t) => ({ label: t.name, value: t.n, href: href("alerts", { tactic: t.name, ...range }) })),
        { unit: "alerts" }))));

    const ucList = d.ours.usecases.sort((a, b) => b.level - a.level || b.hits - a.hits);
    body.append(el("div", { class: "grid2" },
      card("Latest high and critical alerts", { side: el("a", { class: "card-link", href: href("alerts", { level: 12, ...range }) }, "See all") },
        d.latest_high.length ? el("ol", { class: "feedlist" }, d.latest_high.map((h) => {
          const r = h.doc.rule || {};
          const when = parseTs(h.doc.timestamp);
          return el("li", {}, el("button", { type: "button", class: "feedrow", onclick: () => openEvent(h, { range }) },
            levelBadge(r.level), el("span", { class: "feed-what" }, el("span", { class: "feed-desc", text: describe(h.doc) }),
              el("span", { class: "sub", text: `${fmt.stamp(when)}  ${dig(h.doc, "agent.name") || ""}  rule ${r.id}` })),
            h.uc ? el("span", { class: "uc-mini", text: (app.ucByN.get(h.uc) || {}).key }) : null));
        })) : empty("No high or critical alerts in this time range.")),
      el("div", { class: "stack" },
        card("Use cases that fired", { side: el("a", { class: "card-link", href: href("usecases", range) }, "All use cases") },
          ucList.length ? el("ul", { class: "ucfired" }, ucList.map((s) => el("li", {}, ucChip(s.n),
            el("span", { class: "ucf-text" }, (app.ucByN.get(s.n) || {}).title || ""), levelBadge(s.level), el("span", { class: "ucf-n", text: fmt.num(s.hits) }))))
            : empty("None of the 25 use cases fired in this time range.")),
        card("System health", {}, healthList(d.health)))));
  }
}

function tile(label, value, sub, link) {
  return el("a", { class: "tile", href: link }, el("span", { class: "tile-label", text: label }), el("span", { class: "tile-value", text: value }),
    el("span", { class: "tile-sub", text: sub }));
}

/* Pre-flight checklist: each line says what is fine or what to do. */
export function healthList(h) {
  const rows = [];
  const add = (state, title, text) => rows.push(el("li", { class: `hl hl-${state}` },
    el("span", { class: "hl-icon", "aria-hidden": "true", text: state === "ok" ? "✓" : state === "warn" ? "!" : "×" }),
    el("span", { class: "hl-text" }, el("strong", { text: title }), el("span", { text }))));
  const ix = h.indexer || {}, api = h.api || {};
  if (!ix.configured) add("warn", "Indexer", "Not connected. Run: sudo bash install-console.sh --connect");
  else if (!ix.ok) add("bad", "Indexer", ix.error || "Not reachable.");
  else add(ix.cluster === "red" ? "bad" : ix.cluster === "yellow" ? "warn" : "ok", "Indexer", `OpenSearch ${ix.version || ""}, cluster ${ix.cluster || "unknown"}`);
  if (ix.ok) {
    const last = parseTs(ix.latest_alert);
    const age = Number.isFinite(last) ? (Date.now() - last) / 1000 : Infinity;
    add(age < 900 ? "ok" : age < 7200 ? "warn" : "bad", "Alerts arriving", Number.isFinite(last) ? `newest alert ${fmt.ago(last)}` : "no alert in the last 30 days");
    add(ix.archives ? "ok" : "warn", "Raw logs", ix.archives ? `archived, ${fmt.num(ix.archives_24h)} events in 24 hours` : "not archived (Logs page explains how)");
  }
  if (!api.configured) add("warn", "Wazuh server API", "Not connected. Run: sudo bash install-console.sh --connect");
  else if (!api.ok) add("bad", "Wazuh server API", api.error || "Not reachable.");
  else {
    add(api.stopped && api.stopped.length ? "bad" : "ok", "Wazuh server", api.stopped && api.stopped.length ? `stopped: ${api.stopped.join(", ")}` : `${api.version || ""}, all core services running`);
    const a = api.agents || {};
    add(a.disconnected || a.never_connected ? "warn" : "ok", "Agents", `${fmt.num(a.active || 0)} of ${fmt.num(a.total || 0)} active` +
      (a.disconnected ? `, ${a.disconnected} disconnected` : "") + (a.never_connected ? `, ${a.never_connected} never connected` : ""));
  }
  add(h.alerts_file === "following" ? "ok" : "bad", "Live board", h.alerts_file === "following" ? "reading alerts.json" : String(h.alerts_file));
  return el("ul", { class: "health-list" }, rows);
}
