/* MOE console - Live board: the attack path and the departures-style board, fed straight from alerts.json.
   The feed keeps running on every page, so the Live tab can show how many alerts arrived while you were away. */
import { el, $, app, api, fmt, rich, store, recall, levelBand, parseTs, openDrawer, drawerOpen, href, closeDrawer, announce,
         describe } from "./core.js";
import { openEvent } from "./details.js";

const POLL_MS = 2000;
const BOARD_MAX = 200;
const feed = { alerts: [], seq: 0, windowSeq: 0, windowSince: null, agents: {}, serverNow: 0, status: "starting",
               ok: true, started: false, seenSeq: 0, view: null };
// Browser time, like every other page and like "Showing alerts since" (the Wazuh server may run in another time zone).
const clock = (ts) => { const t = parseTs(ts); return Number.isFinite(t) ? fmt.time(t) : ""; };

export function startFeed() {
  if (feed.started) return;
  feed.started = true;
  feed.windowSeq = Number(recall("moe.windowSeq")) || 0;
  feed.windowSince = recall("moe.windowSince") || null;
  poll();
}

async function poll() {
  try {
    const data = await api("/api/alerts", { after: feed.seq });
    if (data.seq < feed.seq) {                       // the console service restarted: start over
      feed.alerts = []; feed.seq = 0; feed.seenSeq = 0;
      if (feed.windowSeq > data.seq) { feed.windowSeq = 0; feed.windowSince = null; }
      return poll();
    }
    const fresh = data.alerts || [];
    const firstLoad = !feed.loadedOnce;
    feed.alerts.push(...fresh);
    if (feed.alerts.length > 5000) feed.alerts.splice(0, feed.alerts.length - 5000);
    feed.seq = data.seq;
    feed.agents = data.agents || {};
    feed.serverNow = data.now || Date.now() / 1000;
    feed.status = data.status;
    feed.ok = true;
    if (feed.windowSeq > feed.seq) { feed.windowSeq = 0; feed.windowSince = null; }
    if (firstLoad) {                       // history, not news: draw it without flips, and it does not count as new
      feed.loadedOnce = true;
      feed.seenSeq = feed.seq;
      if (feed.view) feed.view.reset();
    } else if (feed.view) {
      feed.view.update(fresh);
      feed.seenSeq = feed.seq;
    } else if (fresh.length) badge();
  } catch (err) {
    feed.ok = false;
    if (feed.view) feed.view.banner("Lost contact with the console service. Retrying every few seconds.");
  } finally {
    setTimeout(poll, POLL_MS);
  }
}

function badge() {
  const b = $("live-badge");
  if (!b) return;
  const n = feed.alerts.filter((a) => a.seq > feed.seenSeq && a.seq > feed.windowSeq).length;
  b.hidden = n === 0;
  b.textContent = n > 99 ? "99+" : String(n);
  b.setAttribute("aria-label", `${n} new library alerts`);
}

const windowAlerts = () => feed.alerts.filter((a) => a.seq > feed.windowSeq);

function primaryTactic(uc) {
  const first = String(uc.tactic || "").split("/")[0].trim();
  if (app.cat.tactics.includes(first)) return first;
  const t = app.cat.techniques[uc.techniques[0]];
  return t ? t.tactics[0] : app.cat.tactics[0];
}

export function renderLive(main) {
  const agents = el("ul", { class: "agents", "aria-label": "Agents seen in the alert stream" });
  const label = el("p", { class: "window-label" });
  const banner = el("p", { class: "banner", hidden: true });
  const tactics = el("ol", { class: "tactics" });
  const summary = el("p", { class: "path-summary" });
  const rows = el("ol", { class: "board-rows" });
  const emptyMsg = el("p", { class: "board-empty", text: "No alerts in this window yet. Run a use case from the runbook and it appears here within a few seconds." });
  const count = el("p", { class: "board-count" });

  main.append(
    el("div", { class: "live-bar" }, agents,
      el("div", { class: "window", role: "group", "aria-label": "Alert window" }, label,
        el("div", { class: "actions" },
          el("button", { type: "button", class: "btn btn-primary", onclick: () => setWindow(feed.seq, new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })) }, "Start a fresh window"),
          el("button", { type: "button", class: "btn", onclick: () => setWindow(0, null) }, "Show everything")))),
    banner,
    el("div", { class: "layout" },
      el("section", { class: "path", "aria-labelledby": "path-title" },
        el("div", { class: "path-head" }, el("h1", { id: "path-title", text: "Attack path" }), summary), tactics),
      el("section", { class: "board", "aria-labelledby": "board-title" },
        el("div", { class: "board-head" }, el("h2", { id: "board-title", text: "Live board" }), count),
        el("div", { class: "board-cols", "aria-hidden": "true" }, el("span", { text: "Time" }), el("span", { text: "Level" }),
          el("span", { text: "Use case" }), el("span", { text: "What happened" })),
        rows, emptyMsg)));

  // attack path
  for (const tactic of app.cat.tactics) {
    const ucs = app.cat.usecases.filter((u) => primaryTactic(u) === tactic);
    if (!ucs.length) continue;
    tactics.append(el("li", { class: "tactic", "data-tactic": tactic },
      el("span", { class: "tactic-marker", "aria-hidden": "true" }),
      el("h2", { class: "tactic-name", text: tactic }),
      el("div", { class: "tactic-ucs" }, ucs.map((u) =>
        el("button", { type: "button", class: "uc", id: `uc-${u.n}`, onclick: () => openUseCase(u) },
          el("span", { class: "uc-key", text: u.key }), el("span", { class: "uc-hits" }), el("span", { class: "uc-title", text: u.title }))))));
  }

  function setWindow(seq, since) {
    feed.windowSeq = seq; feed.windowSince = since;
    store("moe.windowSeq", String(seq)); store("moe.windowSince", since || "");
    renderAll(true);
  }

  function renderPath() {
    const stats = new Map();
    for (const a of windowAlerts()) {
      const s = stats.get(a.uc) || { hits: 0, level: 0 };
      s.hits += 1; s.level = Math.max(s.level, Number(a.alert.rule.level) || 0);
      stats.set(a.uc, s);
    }
    let fired = 0, top = 0;
    for (const u of app.cat.usecases) {
      const c = main.querySelector(`#uc-${u.n}`);
      if (!c) continue;
      const s = stats.get(u.n);
      c.querySelector(".uc-hits").textContent = s ? fmt.plural(s.hits, "alert") : "";
      if (s) { c.dataset.level = levelBand(s.level); fired += 1; top = Math.max(top, s.level); } else delete c.dataset.level;
      c.setAttribute("aria-label", `${u.key} ${u.title}` + (s ? `, ${s.hits} alerts, highest level ${s.level}` : ", no alerts"));
    }
    for (const row of main.querySelectorAll(".tactic")) row.dataset.hit = row.querySelector(".uc[data-level]") ? "true" : "false";
    summary.textContent = "";
    const total = windowAlerts().length;
    summary.append(el("strong", { text: `${fired} of ${app.cat.usecases.length}` }), " use cases fired");
    summary.append(fired ? `. Highest level ${top}, ${fmt.plural(total, "alert")}.` : " in this window.");
  }

  function boardRow(item, isNew) {
    const r = item.alert.rule || {};
    const uc = app.ucByN.get(item.uc);
    const agent = (item.alert.agent || {}).name || "";
    return el("li", {}, el("button", { type: "button", class: "row" + (isNew ? " is-new" : ""), onclick: () => openEvent(item) },
      el("span", { class: "row-time", text: clock(item.alert.timestamp) }),
      el("span", { class: "row-level", "data-level": levelBand(Number(r.level)), text: String(r.level ?? "") }),
      el("span", { class: "row-uc", text: uc ? uc.key : "" }),
      el("span", { class: "row-what" }, el("span", { class: "row-desc", text: describe(item.alert) }),
        el("span", { class: "row-agent", text: `${agent}  rule ${r.id}` }))));
  }

  function renderBoard() {
    const items = windowAlerts();
    rows.textContent = "";
    for (const item of items.slice(-BOARD_MAX).reverse()) rows.append(boardRow(item, false));
    emptyMsg.hidden = items.length > 0;
    count.textContent = items.length ? fmt.plural(items.length, "alert") : "";
  }

  function renderAgents() {
    agents.textContent = "";
    for (const name of Object.keys(feed.agents).sort()) {
      const a = feed.agents[name];
      const age = Math.max(0, Math.round(feed.serverNow - parseTs(a.last) / 1000));
      const seen = !Number.isFinite(age) ? "no events yet" : age < 60 ? `last event ${age} s ago`
        : age < 3600 ? `last event ${Math.round(age / 60)} min ago` : `last event ${Math.round(age / 3600)} h ago`;
      agents.append(el("li", { class: "agent", "data-state": age < 300 ? "live" : age < 3600 ? "quiet" : "stale" },
        el("span", { class: "agent-dot", "aria-hidden": "true" }), el("span", { text: a.id === "000" ? "Wazuh server" : name }),
        el("span", { class: "agent-seen", text: seen })));
    }
  }

  function renderAll() {
    label.textContent = feed.windowSeq > 0 && feed.windowSince ? `Showing alerts since ${feed.windowSince}` : "Showing every alert since the console started";
    renderPath(); renderBoard(); renderAgents();
    showBanner(feed.ok ? (feed.status === "following" ? "" : `The console cannot read the Wazuh alert file yet: ${feed.status}. Check that the moe-console service user is in the wazuh group.`)
      : "Lost contact with the console service. Retrying every few seconds.");
  }

  function showBanner(text) { banner.textContent = text || ""; banner.hidden = !text; }

  feed.view = {
    banner: showBanner,
    reset: renderAll,
    update(fresh) {
      let revealed = null;
      for (const item of fresh) {
        if (item.seq <= feed.windowSeq) continue;
        rows.prepend(boardRow(item, true));
        const c = main.querySelector(`#uc-${item.uc}`);
        if (c) { c.classList.remove("just-fired"); void c.offsetWidth; c.classList.add("just-fired"); revealed = c; }
      }
      while (rows.children.length > BOARD_MAX) rows.lastElementChild.remove();
      if (fresh.length) {
        renderPath();
        const items = windowAlerts();
        emptyMsg.hidden = items.length > 0;
        count.textContent = items.length ? fmt.plural(items.length, "alert") : "";
        const last = fresh[fresh.length - 1];
        const uc = app.ucByN.get(last.uc);
        announce(`New alert: ${uc ? uc.key : ""} level ${last.alert.rule.level}. ${describe(last.alert)}`);
      }
      if (revealed && !drawerOpen()) {      // bring the tile that just lit up into view: a live demo never needs scrolling
        const box = revealed.getBoundingClientRect();
        if (box.top < 0 || box.bottom > window.innerHeight) {
          revealed.scrollIntoView({ block: "center", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
        }
      }
      renderAgents();
      showBanner(feed.status === "following" ? "" : `The console cannot read the Wazuh alert file yet: ${feed.status}.`);
    },
  };
  feed.seenSeq = feed.seq;
  badge();
  renderAll();
  return () => { feed.view = null; feed.seenSeq = feed.seq; };
}

export function openUseCase(u) {
  openDrawer((body) => {
    const hits = windowAlerts().filter((a) => a.uc === u.n).slice(-20).reverse();
    const sec = (title, ...c) => el("section", { class: "d-section" }, el("h3", { text: title }), ...c);
    body.append(
      el("p", { class: "d-key", text: u.key }),
      el("h2", { class: "d-title", id: "drawer-title", text: u.title }),
      el("p", { class: "d-meta", text: `Runs on: ${u.where}. Log sources: ${u.sources.join(", ")}.` }),
      el("div", { class: "actions" }, el("a", { class: "btn", href: href(`usecases/${u.key}`), onclick: closeDrawer }, "Open the full page")),
      sec("Why it matters here", el("p", { text: u.say.why })),
      sec("How it works", el("p", { text: u.say.logic })),
      sec("False positives", el("p", { text: u.say.fp })),
      sec("Trigger it live", el("ol", {}, u.test.map((t) => el("li", {}, rich(t))))),
      sec(hits.length ? `Alerts in this window (${hits.length})` : "Alerts in this window",
        hits.length ? el("ul", { class: "d-alerts" }, hits.map((h) => el("li", {},
          el("button", { type: "button", onclick: () => openEvent(h) }, `${clock(h.alert.timestamp)}  level ${h.alert.rule.level}  ${describe(h.alert)}`))))
          : el("p", { class: "d-quiet", text: "None yet. Follow the steps above and the alert appears here and on the live board." })));
  });
}
