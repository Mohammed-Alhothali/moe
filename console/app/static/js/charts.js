/* MOE console - charts. Thin marks, hairline grid, one baseline, hover and keyboard readouts, a table view.
   Severity colours come from CSS custom properties (--lv-low ... --lv-crit), validated for colour-vision deficiency. */
import { el, svg, fmt, LEVELS, showTip, hideTip } from "./core.js";

const INTERVAL_MS = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
export const intervalMs = (iv) => parseInt(iv, 10) * INTERVAL_MS[String(iv).slice(-1)];

function niceMax(v) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function bucketLabel(t, iv, first) {
  const ms = intervalMs(iv);
  if (ms >= 86400000) return fmt.day(t);
  const d = new Date(t);
  if (first || (d.getHours() === 0 && d.getMinutes() === 0)) return `${fmt.day(t)} ${fmt.hm(t)}`;
  return fmt.hm(t);
}

/* Column chart over time. stacked=true splits each column by severity. onPick(bucket) zooms in. */
export function timeColumns(buckets, opts) {
  const o = { height: 170, stacked: true, label: "Alerts over time", unit: "alerts", ...opts };
  const wrap = el("div", { class: "chart" });
  const series = o.stacked ? LEVELS : [{ key: "n", label: o.unit }];
  if (o.stacked) {
    wrap.append(el("ul", { class: "legend", "aria-label": "Severity" }, LEVELS.map((l) =>
      el("li", {}, el("span", { class: `key key-${l.key}`, "aria-hidden": "true" }), `${l.label} (${l.range})`))));
  }
  const plot = el("div", { class: "chart-plot" });
  wrap.append(plot);
  const table = tableView(buckets, o, series);
  wrap.append(table);

  let active = -1;
  const draw = () => {
    const W = Math.max(260, plot.clientWidth || plot.parentElement.clientWidth || 600);
    const H = o.height, left = 44, right = 8, top = 10, bottom = 26;
    const iw = W - left - right, ih = H - top - bottom;
    const n = Math.max(1, buckets.length);
    const slot = iw / n;
    const bw = Math.max(2, Math.min(24, slot - 2));          // capped at 24 px, the rest of the slot is air
    const max = niceMax(Math.max(1, ...buckets.map((b) => b.n || 0)));
    const y = (v) => top + ih - (v / max) * ih;
    const root = svg("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img", tabindex: "0",
      "aria-label": `${o.label}. ${fmt.num(buckets.reduce((s, b) => s + (b.n || 0), 0))} ${o.unit}. Use the arrow keys to read each column.` });
    for (const v of [0, max / 2, max]) {
      root.append(svg("line", { x1: left, x2: W - right, y1: y(v), y2: y(v), class: v === 0 ? "axis" : "grid" }));
      root.append(svg("text", { x: left - 6, y: y(v) + 4, class: "tick", "text-anchor": "end" }, fmt.compact(v)));
    }
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 90))));
    buckets.forEach((b, i) => {
      const cx = left + slot * i + slot / 2;
      const g = svg("g", { class: "col", "data-i": String(i) });
      if (o.stacked) {
        let base = 0;
        const parts = LEVELS.map((l) => ({ key: l.key, v: b[l.key] || 0 })).filter((p) => p.v > 0);
        parts.forEach((p, k) => {
          const y0 = y(base), y1 = y(base + p.v);
          const h = Math.max(1, y0 - y1 - (k > 0 ? 2 : 0));          // 2 px surface gap between segments
          const yTop = y0 - (k > 0 ? 2 : 0) - h;
          g.append(barPath(cx - bw / 2, yTop, bw, h, k === parts.length - 1, `seg seg-${p.key}`));
          base += p.v;
        });
      } else if (b.n > 0) {
        const h = Math.max(1, y(0) - y(b.n));
        g.append(barPath(cx - bw / 2, y(b.n), bw, h, true, "seg seg-one"));
      }
      g.append(svg("rect", { x: left + slot * i, y: top, width: slot, height: ih, class: "hit" }));
      g.addEventListener("pointermove", (e) => { setActive(i); readout(g, b, e); });
      g.addEventListener("pointerleave", () => { setActive(-1); hideTip(); });
      if (o.onPick) g.addEventListener("click", () => o.onPick(b));
      root.append(g);
      if (i % every === 0) {
        root.append(svg("text", { x: cx, y: H - 8, class: "tick", "text-anchor": "middle" }, bucketLabel(b.t, o.interval, i === 0)));
      }
    });
    root.addEventListener("keydown", (e) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End", "Enter"].includes(e.key)) return;
      e.preventDefault();
      if (e.key === "Enter" && active >= 0 && o.onPick) return o.onPick(buckets[active]);
      let i = active < 0 ? buckets.length - 1 : active;
      if (e.key === "ArrowLeft") i = Math.max(0, i - 1);
      if (e.key === "ArrowRight") i = Math.min(buckets.length - 1, i + 1);
      if (e.key === "Home") i = 0;
      if (e.key === "End") i = buckets.length - 1;
      setActive(i);
      const g = root.querySelector(`.col[data-i="${i}"]`);
      if (g) readout(g, buckets[i], { type: "focus" });
    });
    root.addEventListener("blur", () => { setActive(-1); hideTip(); });
    plot.textContent = "";
    plot.append(root);
    function setActive(i) {
      active = i;
      root.querySelectorAll(".col.is-active").forEach((c) => c.classList.remove("is-active"));
      if (i >= 0) { const g = root.querySelector(`.col[data-i="${i}"]`); if (g) g.classList.add("is-active"); }
    }
  };

  function readout(target, b, evt) {
    showTip(target, (tip) => {
      const end = b.t + intervalMs(o.interval);
      tip.append(el("p", { class: "tip-title" }, `${fmt.stamp(b.t)} to ${fmt.hm(end)}`));
      const rows = el("dl", { class: "tip-rows" });
      if (o.stacked) {
        for (const l of [...LEVELS].reverse()) {
          rows.append(el("div", {}, el("dt", {}, el("span", { class: `tkey key-${l.key}`, "aria-hidden": "true" }), l.label),
            el("dd", { text: fmt.num(b[l.key] || 0) })));
        }
      }
      rows.append(el("div", { class: "tip-total" }, el("dt", { text: "Total" }), el("dd", { text: fmt.num(b.n || 0) })));
      tip.append(rows);
      if (o.onPick) tip.append(el("p", { class: "tip-hint" }, "Click to zoom into this period"));
    }, evt);
  }

  // draw when attached and on resize
  const ro = new ResizeObserver(() => draw());
  ro.observe(plot);
  requestAnimationFrame(draw);
  return wrap;
}

/* A bar with a 4 px rounded data-end (top) and a square base. */
function barPath(x, yTop, w, h, roundTop, cls) {
  const r = roundTop ? Math.min(4, w / 2, h) : 0;
  const d = `M${x},${yTop + h} V${yTop + r} Q${x},${yTop} ${x + r},${yTop} H${x + w - r} Q${x + w},${yTop} ${x + w},${yTop + r} V${yTop + h} Z`;
  return svg("path", { d, class: cls });
}

function tableView(buckets, o, series) {
  const rows = buckets.filter((b) => b.n > 0);
  const det = el("details", { class: "chart-table" }, el("summary", {}, "Show the numbers as a table"));
  const t = el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "From" }),
      series.map((s) => el("th", { scope: "col", class: "num", text: s.label })),
      o.stacked ? el("th", { scope: "col", class: "num", text: "Total" }) : null)),
    el("tbody", {}, rows.map((b) => el("tr", {}, el("td", { text: fmt.stamp(b.t) }),
      series.map((s) => el("td", { class: "num", text: fmt.num(o.stacked ? b[s.key] || 0 : b.n) })),
      o.stacked ? el("td", { class: "num", text: fmt.num(b.n) }) : null))));
  det.append(rows.length ? t : el("p", { class: "empty", text: "No data in this time range." }));
  return det;
}

/* Ranked horizontal bars (HTML). items: [{label, value, href?|onclick?, lead?, title?}] */
export function rankBars(items, opts) {
  const o = { unit: "alerts", ...opts };
  if (!items.length) return el("p", { class: "empty", text: o.empty || "Nothing in this time range." });
  const max = Math.max(...items.map((i) => i.value), 1);
  return el("ol", { class: "rank" }, items.map((it) => {
    const inner = [
      el("span", { class: "rank-label" }, it.lead || null, el("span", { class: "rank-text", title: it.title || it.label }, it.label)),
      el("span", { class: "rank-track", "aria-hidden": "true" }, el("span", { class: "rank-bar", style: `width:${Math.max(1.5, (it.value / max) * 100)}%` })),
      el("span", { class: "rank-value", text: fmt.num(it.value) })];
    const label = `${it.title || it.label}: ${fmt.num(it.value)} ${o.unit}`;
    return el("li", {}, it.href ? el("a", { class: "rank-row", href: it.href, "aria-label": label }, inner)
      : it.onclick ? el("button", { type: "button", class: "rank-row", onclick: it.onclick, "aria-label": label }, inner)
        : el("div", { class: "rank-row" }, inner));
  }));
}

/* A meter: share of a whole, with the track a lighter step of the same hue. */
export function meter(value, max, label) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return el("div", { class: "meter", role: "meter", "aria-valuemin": "0", "aria-valuemax": String(max), "aria-valuenow": String(value),
    "aria-label": label }, el("span", { class: "meter-fill", style: `width:${pct}%` }));
}

/* Tall segmented bar for the severity split (one whole, four parts, labels inside when they fit). */
export function severitySplit(levels, total) {
  if (!total) return el("p", { class: "empty", text: "No alerts in this time range." });
  const bar = el("div", { class: "split", role: "img",
    "aria-label": LEVELS.map((l) => `${l.label} ${fmt.num(levels[l.key] || 0)}`).join(", ") });
  for (const l of LEVELS) {
    const v = levels[l.key] || 0;
    if (!v) continue;
    const share = v / total;
    const part = el("span", { class: `split-part split-${l.key}`, style: `flex-grow:${v}`, tabindex: "0",
      "aria-label": `${l.label}: ${fmt.num(v)} (${Math.round(share * 100)}%)` },
      share >= 0.09 ? el("span", { class: "split-label", text: `${Math.round(share * 100)}%` }) : null);
    const tip = (e) => showTip(part, (t) => {
      t.append(el("p", { class: "tip-title", text: `${l.label} (${l.range})` }),
        el("p", { class: "tip-value", text: `${fmt.num(v)} alerts, ${Math.round(share * 100)}%` }));
    }, e);
    part.addEventListener("pointermove", tip);
    part.addEventListener("focus", tip);
    part.addEventListener("pointerleave", hideTip);
    part.addEventListener("blur", hideTip);
    bar.append(part);
  }
  return el("div", { class: "split-wrap" }, bar,
    el("ul", { class: "legend" }, LEVELS.map((l) => el("li", {}, el("span", { class: `key key-${l.key}`, "aria-hidden": "true" }),
      `${l.label} ${fmt.num(levels[l.key] || 0)}`))));
}
