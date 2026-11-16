/* MOE console - shared helpers.
   Every value that comes from Wazuh (alerts, logs, agent names, rule text) is attacker-controlled, so it is only
   ever written with textContent / createTextNode - never as HTML. */

export const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";

export function el(tag, props, ...children) {
  const node = document.createElement(tag);
  setProps(node, props);
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function svg(tag, props, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  setProps(node, props);
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function setProps(node, props) {
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.setAttribute("class", v);
    else if (k === "text") node.textContent = v;
    else if (k === "style") {       // through the CSSOM: the CSP forbids style attributes, not style properties
      for (const decl of String(v).split(";")) {
        const at = decl.indexOf(":");
        if (at > 0) node.style.setProperty(decl.slice(0, at).trim(), decl.slice(at + 1).trim());
      }
    }
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
}

/* Catalogue text uses `code` and **bold** from the runbook. Turn those into elements, everything else stays text. */
export function rich(text) {
  const frag = document.createDocumentFragment();
  for (const part of String(text ?? "").split(/(`[^`]+`|\*\*[^*]+\*\*)/)) {
    if (!part) continue;
    if (part.startsWith("`") && part.endsWith("`")) frag.append(el("code", { text: part.slice(1, -1) }));
    else if (part.startsWith("**") && part.endsWith("**")) frag.append(el("strong", { text: part.slice(2, -2) }));
    else frag.append(document.createTextNode(part));
  }
  return frag;
}

export function store(key, value) { try { localStorage.setItem(key, value); } catch (e) { /* private mode */ } }
export function recall(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }

/* ---------------- shared state ---------------- */
export const app = { cat: null, ucByN: new Map(), status: null, range: { range: "24h" }, lastFocus: null };

export async function loadCatalogue() {
  const res = await fetch("/static/usecases.json", { cache: "no-store" });
  app.cat = await res.json();
  for (const u of app.cat.usecases) app.ucByN.set(u.n, u);
}

/* ---------------- severity ---------------- */
export const LEVELS = [
  { key: "low", label: "Low", range: "0-6" }, { key: "med", label: "Medium", range: "7-11" },
  { key: "high", label: "High", range: "12-14" }, { key: "crit", label: "Critical", range: "15+" }];
export const levelBand = (l) => (l >= 15 ? "crit" : l >= 12 ? "high" : l >= 7 ? "med" : "low");
export const levelName = (l) => LEVELS.find((x) => x.key === levelBand(Number(l) || 0)).label;

export function levelBadge(level, extra) {
  const l = Number(level);
  return el("span", { class: `lv lv-${levelBand(l)}${extra ? " " + extra : ""}`, title: `Level ${l}: ${levelName(l)}` },
    Number.isFinite(l) ? String(l) : "");
}

/* ---------------- formatting ---------------- */
export const fmt = {
  num: (n) => Number(n || 0).toLocaleString("en-US"),
  compact: (n) => {
    n = Number(n || 0);
    if (n < 10000) return n.toLocaleString("en-US");
    if (n < 1e6) return `${(n / 1e3).toFixed(n < 1e5 ? 1 : 0).replace(/\.0$/, "")}K`;
    return `${(n / 1e6).toFixed(1).replace(/\.0$/, "")}M`;
  },
  time: (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }),
  hm: (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false }),
  day: (ms) => new Date(ms).toLocaleDateString([], { day: "numeric", month: "short" }),
  stamp: (ms) => {
    const d = new Date(ms);
    const today = new Date();
    const sameDay = d.toDateString() === today.toDateString();
    return sameDay ? fmt.time(ms) : `${fmt.day(ms)} ${fmt.time(ms)}`;
  },
  ago: (ms) => {
    if (!ms || !Number.isFinite(ms)) return "never";
    const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (s < 60) return `${s} s ago`;
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} days ago`;
  },
  plural: (n, one, many) => `${fmt.num(n)} ${Number(n) === 1 ? one : (many || one + "s")}`,
};

export const parseTs = (ts) => Date.parse(String(ts || "").replace(/([+-]\d\d)(\d\d)$/, "$1:$2"));

/* Wazuh copies Windows values escaped: backslashes doubled, quotes as \" and <, >, & written as entities
   (C:\\Users, \"cmd.exe\", 2^&gt;^&amp;1). One-line texts in lists show them the way they were typed; the event
   details keep the raw values, which are what a rule has to match. */
const ENTITY = { "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"', "&apos;": "'", "&#39;": "'" };
export function readable(text, windows) {
  const t = String(text ?? "").replace(/&(?:lt|gt|amp|quot|apos|#39);/g, (m) => ENTITY[m]);
  return windows ? t.replace(/\\(["\\])/g, "$1") : t;     // one pass: \\ -> \ and \" -> "
}
export const isWindows = (doc) => !!doc && (doc.location === "EventChannel" || !!(doc.data && doc.data.win));
export const describe = (doc) => readable((doc && doc.rule && doc.rule.description) || "", isWindows(doc));

export function dig(obj, path) {
  let cur = obj;
  for (const part of path.split(".")) {
    if (cur === null || cur === undefined || typeof cur !== "object") return undefined;
    cur = cur[part];
  }
  return cur;
}

/* Flatten a document into [path, value] pairs; arrays of scalars stay together. */
export function flatten(obj, prefix = "", out = []) {
  if (obj === null || obj === undefined) return out;
  if (Array.isArray(obj) && obj.every((v) => typeof v !== "object" || v === null)) {
    out.push([prefix, obj.join(", ")]);
    return out;
  }
  if (typeof obj !== "object") { out.push([prefix, String(obj)]); return out; }
  for (const [k, v] of Object.entries(obj)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
  return out;
}

/* ---------------- server calls ---------------- */
export class ApiError extends Error {
  constructor(message, status, setup) { super(message); this.status = status; this.setup = setup; }
}

export function query(params) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null || v === "" || v === false) continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else sp.append(k, String(v));
  }
  return sp.toString();
}

export async function api(path, params) {
  const qs = query(params);
  let res;
  try {
    res = await fetch(`${path}${qs ? "?" + qs : ""}`, { cache: "no-store", credentials: "same-origin" });
  } catch (e) {
    throw new ApiError("Lost contact with the console service. Check that it is running: systemctl status moe-console", 0);
  }
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) throw new ApiError((data && data.error) || `The console answered ${res.status}.`, res.status, data && data.setup);
  return data;
}

export async function post(path, body) {
  const res = await fetch(path, {
    method: "POST", credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-MOE-Request": "1" }, body: JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) throw new ApiError((data && data.error) || `The console answered ${res.status}.`, res.status);
  return data;
}

/* ---------------- routing ---------------- */
export function currentRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, qs] = raw.split("?");
  return { parts: (path || "live").split("/").filter(Boolean), params: new URLSearchParams(qs || "") };
}

export function href(path, params) {
  const qs = query(params);
  return `#/${path}${qs ? "?" + qs : ""}`;
}

export function go(path, params) { location.hash = href(path, params); }

/* Time range in the URL: range=24h, or range=custom&from=<ms>&to=<ms>. Remembered between pages. */
export function rangeFrom(params) {
  const r = params.get("range");
  if (r === "custom" && params.get("from")) return { range: "custom", from: params.get("from"), to: params.get("to") || "" };
  if (r) return { range: r };
  return { ...app.range };
}

export const RANGE_LABELS = { "15m": "15 min", "1h": "1 hour", "4h": "4 hours", "24h": "24 hours", "7d": "7 days", "30d": "30 days" };

export function rangeText(r) {
  if (r.range === "custom") return `${fmt.stamp(Number(r.from))} to ${r.to ? fmt.stamp(Number(r.to)) : "now"}`;
  return `last ${RANGE_LABELS[r.range] || r.range}`;
}

/* Preset buttons first, a custom range behind them (dataviz: date range is the first filter). */
export function timeControl(current, onChange) {
  const wrap = el("div", { class: "timectl", role: "group", "aria-label": "Time range" });
  const presets = ["15m", "1h", "24h", "7d", "30d"];
  for (const p of presets) {
    wrap.append(el("button", { type: "button", class: "seg", "aria-pressed": String(current.range === p),
      onclick: () => onChange({ range: p }) }, RANGE_LABELS[p]));
  }
  const customBtn = el("button", { type: "button", class: "seg", "aria-pressed": String(current.range === "custom"),
    "aria-expanded": "false" }, current.range === "custom" ? rangeText(current) : "Custom");
  const toLocal = (ms) => {
    const d = new Date(Number(ms));
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  };
  const now = Date.now();
  const from = el("input", { type: "datetime-local", value: toLocal(current.from || now - 3600000), "aria-label": "From" });
  const to = el("input", { type: "datetime-local", value: toLocal(current.to || now), "aria-label": "To" });
  const pop = el("div", { class: "timepop", hidden: true },
    el("label", {}, "From", from), el("label", {}, "To", to),
    el("button", { type: "button", class: "btn btn-primary", onclick: () => {
      const f = new Date(from.value).getTime(), t = new Date(to.value).getTime();
      if (!(f < t)) { from.setCustomValidity("Start must be before end"); from.reportValidity(); return; }
      onChange({ range: "custom", from: String(f), to: String(t) });
    } }, "Apply"));
  customBtn.addEventListener("click", () => {
    pop.hidden = !pop.hidden;
    customBtn.setAttribute("aria-expanded", String(!pop.hidden));
    if (!pop.hidden) from.focus();
  });
  wrap.append(el("div", { class: "timecustom" }, customBtn, pop));
  return wrap;
}

/* ---------------- page furniture ---------------- */
export function pageHead(title, lede, ...side) {
  return el("div", { class: "page-head" },
    el("div", { class: "page-title" }, el("h1", { text: title }), lede ? el("p", { class: "lede" }, lede) : null),
    side.length ? el("div", { class: "page-side" }, side) : null);
}

export function card(title, opts, ...content) {
  opts = opts || {};
  return el("section", { class: `card${opts.class ? " " + opts.class : ""}`, "aria-label": title },
    el("div", { class: "card-head" }, el("h2", { text: title }), opts.side || null),
    ...content);
}

export function notice(kind, text, ...extra) {
  return el("div", { class: `notice notice-${kind}`, role: kind === "error" ? "alert" : "status" }, el("p", {}, text), ...extra);
}

export function errorNotice(err) {
  const setup = err && err.setup;
  const text = (err && err.message) || "Something went wrong.";
  return notice(setup ? "setup" : "error", text);
}

export function empty(text) { return el("p", { class: "empty", text }); }

export function chip(text, props) { return el("span", { class: "chip", ...(props || {}) }, text); }

export function ucChip(n, opts) {
  const u = app.ucByN.get(Number(n));
  if (!u) return null;
  return el("a", { class: "uc-chip", href: href(`usecases/${u.key}`), title: u.title, ...(opts || {}) }, u.key);
}

export function busy(node, on) {
  node.classList.toggle("is-loading", !!on);
  node.setAttribute("aria-busy", on ? "true" : "false");
}

export function announce(text) { const a = $("announcer"); if (a) a.textContent = text; }

export function toast(text) {
  const t = el("div", { class: "toast", role: "status" }, text);
  document.body.append(t);
  setTimeout(() => t.classList.add("is-out"), 2200);
  setTimeout(() => t.remove(), 2700);
}

export async function copyText(text, button, label) {
  const original = label || button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
  } catch (e) {
    button.textContent = "Copy failed";
  }
  setTimeout(() => { button.textContent = original; }, 1500);
}

/* ---------------- tooltip (one element, positioned at the pointer or the focused mark) ---------------- */
export function showTip(target, build, evt) {
  const tip = $("tip");
  tip.textContent = "";
  build(tip);
  tip.hidden = false;
  const box = tip.getBoundingClientRect();
  let x, y;
  if (evt && evt.clientX !== undefined && evt.type !== "focus") { x = evt.clientX + 14; y = evt.clientY + 14; }
  else { const r = target.getBoundingClientRect(); x = r.left + r.width / 2 + 8; y = r.top - box.height - 8; }
  x = Math.min(x, window.innerWidth - box.width - 8);
  if (y + box.height > window.innerHeight - 8) y = (evt && evt.clientY ? evt.clientY : 0) - box.height - 12;
  tip.style.left = `${Math.max(8, x)}px`;
  tip.style.top = `${Math.max(8, y)}px`;
}
export function hideTip() { const tip = $("tip"); if (tip) tip.hidden = true; }

/* ---------------- drawer ---------------- */
export function openDrawer(build, opts) {
  app.lastFocus = document.activeElement;
  const body = $("drawer-body");
  body.textContent = "";
  $("drawer").classList.toggle("drawer-wide", !!(opts && opts.wide));
  build(body);
  $("drawer").hidden = false;
  $("backdrop").hidden = false;
  $("drawer").scrollTop = 0;
  $("drawer-close").focus();
}
export function closeDrawer() {
  $("drawer").hidden = true;
  $("backdrop").hidden = true;
  if (app.lastFocus && document.contains(app.lastFocus)) app.lastFocus.focus();
}
export const drawerOpen = () => !$("drawer").hidden;
