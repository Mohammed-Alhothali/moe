/* MOE console - ATT&CK coverage: which techniques our use cases detect, and which ones fired in the chosen time. */
import { el, app, api, fmt, go, rangeFrom, rangeText, timeControl, pageHead, errorNotice, busy } from "./core.js";
import { openTechnique } from "./details.js";

// Reconnaissance and Resource Development happen before an attacker touches our systems; host logs cannot see them,
// so the matrix shows the 12 tactics an endpoint SIEM can cover and says so in a note.
const ALL_TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
const heat = (n) => (n >= 20 ? 3 : n >= 5 ? 2 : n >= 1 ? 1 : 0);

export function renderAttack(main, params) {
  const range = rangeFrom(params);
  if (range.range !== "custom") app.range = { range: range.range };
  main.append(pageHead("ATT&CK coverage", "Each column is a step of an attack. Green-edged cells are techniques our use cases detect; the fill shows how often they fired."));
  main.append(el("div", { class: "filters" }, timeControl(range, (r) => go("attack", r))));
  const body = el("div", {});
  main.append(body);
  busy(body, true);
  (async () => {
    let d;
    try { d = await api("/api/attack", range); } catch (e) { body.append(errorNotice(e)); busy(body, false); return; }
    busy(body, false);
    const seen = d.techniques;
    const ucsFor = (tid) => app.cat.usecases.filter((u) => u.techniques.includes(tid));
    const columns = new Map(ALL_TACTICS.map((t) => [t, []]));
    const covered = new Set(Object.keys(app.cat.techniques));
    for (const [tid, t] of Object.entries(app.cat.techniques)) {
      for (const tac of t.tactics) if (columns.has(tac)) columns.get(tac).push({ tid, name: t.name, ours: true });
    }
    for (const [tid, s] of Object.entries(seen)) {
      if (covered.has(tid)) continue;
      for (const tac of (s.tactics || [])) if (columns.has(tac)) columns.get(tac).push({ tid, name: s.name, ours: false });
    }
    const coveredTactics = ALL_TACTICS.filter((t) => columns.get(t).some((c) => c.ours)).length;
    const firedTech = Object.values(seen).filter((s) => s.all > 0).length;
    const firedOurs = Object.entries(seen).filter(([tid, s]) => covered.has(tid) && s.ours > 0).length;
    body.append(el("p", { class: "attack-summary" },
      el("strong", { text: `${covered.size} techniques` }), ` across ${coveredTactics} of the 14 ATT&CK tactics are covered by our ${app.cat.usecases.length} use cases. `,
      `In the ${rangeText(range)}, ${fmt.plural(firedTech, "technique")} appeared in alerts, ${firedOurs} of them through our own rules.`));
    body.append(el("p", { class: "matrix-note", text: "Not shown: Reconnaissance and Resource Development. They happen before the attacker touches our systems, so agent logs cannot see them." }));
    body.append(el("ul", { class: "legend attack-legend" },
      el("li", {}, el("span", { class: "akey akey-ours", "aria-hidden": "true" }), "Detected by our use cases"),
      el("li", {}, el("span", { class: "akey akey-seen", "aria-hidden": "true" }), "Seen only from built-in Wazuh rules"),
      el("li", { class: "heat-legend" }, "Alerts in this time:",
        [["0", 0], ["1-4", 1], ["5-19", 2], ["20+", 3]].map(([t, h]) => el("span", { class: `hk heat-${h}` }, t)))));

    const grid = el("div", { class: "matrix", role: "list" });
    for (const tac of ALL_TACTICS) {
      const cells = columns.get(tac).sort((a, b) => (b.ours - a.ours) || a.tid.localeCompare(b.tid));
      const total = cells.reduce((s, c) => s + ((seen[c.tid] || {}).all || 0), 0);
      const col = el("section", { class: "mcol", role: "listitem", "aria-label": tac },
        el("h2", { class: "mcol-head" }, el("span", { text: tac }),
          el("span", { class: "mcol-sub", text: cells.length ? `${cells.filter((c) => c.ours).length} covered, ${fmt.num(total)} alerts` : "" })));
      if (!cells.length) col.append(el("p", { class: "mcol-empty", text: "No technique here yet." }));
      for (const c of cells) {
        const s = seen[c.tid] || { all: 0, ours: 0, name: c.name, tactics: [] };
        const ucs = c.ours ? ucsFor(c.tid) : [];
        col.append(el("button", { type: "button", class: `mcell ${c.ours ? "is-ours" : "is-seen"} heat-${heat(s.all)}`,
          "aria-label": `${c.tid} ${c.name}. ${c.ours ? `Detected by ${ucs.map((u) => u.key).join(", ")}` : "Built-in rules only"}. ${s.all} alerts.`,
          onclick: () => openTechnique(c.tid, s, range) },
          el("span", { class: "mcell-id", text: c.tid }), el("span", { class: "mcell-n", text: s.all ? fmt.compact(s.all) : "" }),
          el("span", { class: "mcell-name", text: c.name || "" }),
          ucs.length ? el("span", { class: "mcell-ucs", text: ucs.map((u) => u.key).join(" ") }) : null));
      }
      grid.append(col);
    }
    body.append(el("div", { class: "matrix-wrap" }, grid));
    const want = params.get("t");
    if (want) openTechnique(want, seen[want], range);
  })();
}
