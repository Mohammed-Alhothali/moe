/* MOE console - start-up, navigation and the health indicator. */
import { $, el, app, api, loadCatalogue, currentRoute, closeDrawer, drawerOpen, hideTip, href, openDrawer, store, recall } from "./core.js";
import { startFeed, renderLive } from "./live.js";
import { renderOverview, healthList } from "./overview.js";
import { renderSearch } from "./search.js";
import { renderAgents, renderAgent } from "./agents.js";
import { renderAttack } from "./attack.js";
import { renderUseCases, renderUseCase } from "./usecases.js";

const TITLES = { live: "Live", overview: "Overview", alerts: "Alerts", logs: "Logs", agents: "Agents", attack: "ATT&CK", usecases: "Use cases" };
const RANGED = new Set(["overview", "alerts", "logs", "agents", "attack", "usecases"]);
let cleanup = null;
let firstRoute = true;

function route() {
  if (cleanup) { try { cleanup(); } catch (e) { /* ignore */ } cleanup = null; }
  hideTip();
  if (drawerOpen()) closeDrawer();
  const { parts, params } = currentRoute();
  const section = parts[0];
  const main = $("view");
  main.textContent = "";
  main.className = `view view-${section}`;
  switch (section) {
    case "live": cleanup = renderLive(main); break;
    case "overview": cleanup = renderOverview(main, params); break;
    case "alerts": cleanup = renderSearch(main, "alerts", params); break;
    case "logs": cleanup = renderSearch(main, "logs", params); break;
    case "agents": cleanup = parts[1] ? renderAgent(main, parts[1], params) : renderAgents(main, params); break;
    case "attack": cleanup = renderAttack(main, params); break;
    case "usecases": cleanup = parts[1] ? renderUseCase(main, decodeURIComponent(parts[1]), params) : renderUseCases(main, params); break;
    default: location.replace("#/live"); return;
  }
  const r = app.range.range && app.range.range !== "custom" ? { range: app.range.range } : {};
  for (const a of document.querySelectorAll(".nav a")) {
    const k = a.dataset.route;
    a.href = RANGED.has(k) ? href(k, r) : href(k);
    if (k === section) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  document.title = `${TITLES[section] || "MOE"}: MOE SOC console`;
  store("moe.lastRoute", location.hash);
  if (!firstRoute) {
    window.scrollTo(0, 0);
    const h1 = main.querySelector("h1");
    if (h1) { h1.setAttribute("tabindex", "-1"); h1.focus({ preventScroll: true }); }
  }
  firstRoute = false;
}

async function health() {
  const pill = $("health");
  try {
    const s = await api("/api/status");
    app.status = s;
    const h = s.health;
    const bad = (h.indexer.configured && !h.indexer.ok) || (h.api.configured && !h.api.ok) || h.alerts_file !== "following"
      || (h.api.stopped && h.api.stopped.length);
    const setup = !h.indexer.configured || !h.api.configured;
    const ag = h.api.agents;
    const agentsDown = ag && (ag.disconnected || ag.never_connected);
    pill.dataset.state = bad ? "bad" : setup || agentsDown ? "warn" : "ok";
    pill.querySelector(".health-text").textContent = bad ? "Needs attention" : setup ? "Setup incomplete"
      : agentsDown ? `${ag.active} of ${ag.total} agents active` : ag ? `All ${ag.total} agents active` : "Healthy";
  } catch (e) {
    pill.dataset.state = "bad";
    pill.querySelector(".health-text").textContent = "Console unreachable";
  }
}

function openHealth() {
  openDrawer((body) => {
    body.append(el("p", { class: "d-key", text: "System health" }), el("h2", { class: "d-title", id: "drawer-title", text: "Is everything flowing?" }),
      el("p", { class: "d-meta", text: "Check this before a demo: every line should have a tick." }));
    if (app.status) {
      body.append(healthList(app.status.health),
        el("section", { class: "d-section" }, el("h3", { text: "This console" }),
          el("dl", { class: "kv" },
            el("dt", { text: "Version" }), el("dd", { text: app.status.version }),
            ...(app.status.demo ? [el("dt", { text: "Data" }), el("dd", { text: "sample data from demo/run_demo.py" })] : []),
            el("dt", { text: "Signed in as" }), el("dd", { text: app.status.login === false ? "nobody: sign-in is off (install-console.sh --login turns it back on)" : app.status.user }),
            el("dt", { text: "Detection library" }), el("dd", { text: `${app.status.catalogue.usecases} use cases, ${app.status.catalogue.rules} alerting rules` }),
            el("dt", { text: "Rule files readable" }), el("dd", { text: app.status.rules.error || `${app.status.rules.count.toLocaleString("en-US")} rules` }),
            el("dt", { text: "Triage notes" }), el("dd", { text: app.status.triage === "disk" ? "saved on the server" : "kept in memory only (state folder not writable)" }))));
    } else body.append(el("p", { text: "Status not loaded yet." }));
  });
}

function initTheme() {
  const saved = recall("moe.theme");
  const apply = (theme) => {
    document.documentElement.dataset.theme = theme;
    $("theme").textContent = theme === "dark" ? "Light" : "Dark";
    $("theme").setAttribute("aria-label", theme === "dark" ? "Switch to the light theme" : "Switch to the dark theme");
  };
  apply(saved === "light" ? "light" : "dark");      // dark unless the analyst chose light
  $("theme").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    store("moe.theme", next);
    apply(next);
  });
}

async function boot() {
  await loadCatalogue();
  $("org").textContent = app.cat.organisation;
  initTheme();
  const saved = recall("moe.range");
  if (saved && /^(15m|1h|4h|24h|7d|30d)$/.test(saved)) app.range = { range: saved };
  $("drawer-close").addEventListener("click", closeDrawer);
  $("backdrop").addEventListener("click", closeDrawer);
  $("health").addEventListener("click", openHealth);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && drawerOpen()) closeDrawer();
    if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
      const q = document.querySelector(".q");
      if (q) { e.preventDefault(); q.focus(); q.select(); }
    }
  });
  window.addEventListener("hashchange", () => { store("moe.range", app.range.range || "24h"); route(); });
  window.addEventListener("scroll", hideTip, { passive: true });
  startFeed();
  if (!location.hash) location.replace("#/live");
  route();
  health();
  setInterval(health, 30000);
}

boot();
