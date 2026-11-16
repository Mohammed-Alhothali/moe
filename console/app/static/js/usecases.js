/* MOE console - Use cases: the detection library, one page per use case with its rules, logic, tests and live alerts. */
import { el, app, api, fmt, href, go, rich, rangeFrom, rangeText, timeControl, pageHead, card, errorNotice, empty, levelBadge,
         levelBand, busy, parseTs, dig, copyText, describe } from "./core.js";
import { openEvent, openRule, xmlView } from "./details.js";

function primaryTactic(uc) {
  const first = String(uc.tactic || "").split("/")[0].trim();
  if (app.cat.tactics.includes(first)) return first;
  const t = app.cat.techniques[uc.techniques[0]];
  return t ? t.tactics[0] : app.cat.tactics[0];
}

export function renderUseCases(main, params) {
  const range = rangeFrom(params);
  if (range.range !== "custom") app.range = { range: range.range };
  const alerting = app.cat.usecases.reduce((s, u) => s + u.rules.filter((r) => !r.silent && !r.tuning).length, 0);
  const cases = app.cat.usecases.reduce((s, u) => s + u.cases.length, 0);
  main.append(pageHead("Use cases", `${app.cat.usecases.length} detections written for ${app.cat.organisation}: ${alerting} alerting rules, each proven by regression cases (${cases} in total).`));
  main.append(el("div", { class: "filters" }, timeControl(range, (r) => go("usecases", r))));
  const status = el("p", { class: "fine" });
  const groups = el("div", { class: "ucgroups" });
  main.append(status, groups);
  for (const tactic of app.cat.tactics) {
    const ucs = app.cat.usecases.filter((u) => primaryTactic(u) === tactic);
    if (!ucs.length) continue;
    groups.append(el("section", { class: "ucgroup", "aria-label": tactic }, el("h2", { text: tactic }),
      el("div", { class: "uccards" }, ucs.map((u) => el("a", { class: "uccard", href: href(`usecases/${u.key}`, range), id: `ucc-${u.n}` },
        el("span", { class: "ucc-top" }, el("span", { class: "ucc-key", text: u.key }), el("span", { class: "ucc-stat" })),
        el("span", { class: "ucc-title", text: u.title }),
        el("span", { class: "ucc-where", text: u.where }),
        el("span", { class: "ucc-tech", text: u.techniques.join("  ") }))))));
  }
  busy(groups, true);
  (async () => {
    try {
      const d = await api("/api/usecases", range);
      for (const s of d.usecases) {
        const c = groups.querySelector(`#ucc-${s.n}`);
        if (!c) continue;
        c.dataset.level = levelBand(s.level);
        c.querySelector(".ucc-stat").append(levelBadge(s.level), ` ${fmt.plural(s.hits, "alert")}`);
      }
      status.textContent = `${d.usecases.length} of ${app.cat.usecases.length} fired in the ${rangeText(range)}.`;
    } catch (e) {
      status.textContent = `Alert counts are not available: ${e.message}`;
    } finally { busy(groups, false); }
  })();
}

function withCopy(text) {
  const frag = rich(text);
  const wrap = el("span", {});
  wrap.append(frag);
  for (const code of [...wrap.querySelectorAll("code")]) {
    if (code.textContent.length < 18) continue;
    const b = el("button", { type: "button", class: "copy-mini", "aria-label": `Copy: ${code.textContent}` }, "Copy");
    b.addEventListener("click", () => copyText(code.textContent, b, "Copy"));
    code.after(b);
  }
  return wrap;
}

export function renderUseCase(main, key, params) {
  const u = app.cat.usecases.find((x) => x.key.toLowerCase() === String(key).toLowerCase());
  const range = rangeFrom(params);
  main.append(el("p", { class: "crumbs" }, el("a", { href: href("usecases", range) }, "Use cases"), ` / ${key}`));
  if (!u) { main.append(empty("No such use case.")); return; }
  const idx = app.cat.usecases.indexOf(u);
  const prev = app.cat.usecases[idx - 1], next = app.cat.usecases[idx + 1];
  main.append(el("div", { class: "page-head" },
    el("div", { class: "page-title" }, el("p", { class: "uc-bigkey", text: u.key }), el("h1", { text: u.title }), el("p", { class: "lede", text: u.why_long })),
    el("div", { class: "page-side" },
      el("a", { class: "btn btn-primary", href: href("alerts", { uc: u.n, ...range }) }, "Its alerts"),
      prev ? el("a", { class: "btn", href: href(`usecases/${prev.key}`, range), title: prev.title }, `Previous: ${prev.key}`) : null,
      next ? el("a", { class: "btn", href: href(`usecases/${next.key}`, range), title: next.title }, `Next: ${next.key}`) : null)));
  main.append(el("ul", { class: "techline" }, u.techniques.map((t) => el("li", {},
    el("a", { href: href("attack", { t, ...range }) }, el("strong", { text: t }), ` ${(app.cat.techniques[t] || {}).name || ""}`)))));

  const alertsBox = el("div", {}, el("p", { class: "d-quiet", text: "Loading..." }));
  const visible = u.rules.filter((r) => !r.silent && !r.tuning);
  const hidden = u.rules.filter((r) => r.silent || r.tuning);
  const ruleRow = (r) => el("li", { class: "rulerow" },
    el("div", { class: "rule-head" }, levelBadge(r.level), el("button", { type: "button", class: "rule-id linklike", onclick: () => openRule(r.id) }, r.id),
      el("span", { class: "rule-desc", text: r.description }),
      r.tuning ? el("span", { class: "note", text: "Tuning rule: silences a false positive found in the lab." })
        : r.silent ? el("span", { class: "note", text: "Silent: counted for correlation, never shown as an alert." }) : null),
    el("details", { class: "rule-xml" }, el("summary", {}, "Rule XML"), xmlView((app.cat.rule_xml[r.id] || {}).xml || "")));

  const left = el("div", { class: "ucmain" },
    card("How it detects", {}, el("ul", { class: "bullets" }, u.logic.map((x) => el("li", {}, rich(x))))),
    card(`Rules (${visible.length} alerting${hidden.length ? `, ${hidden.length} supporting` : ""})`, {},
      el("ol", { class: "rules" }, visible.map(ruleRow)),
      hidden.length ? el("ol", { class: "rules rules-hidden" }, hidden.map(ruleRow)) : null,
      u.base_rules.length ? el("details", { class: "more-xml" }, el("summary", {}, `Base rules it builds on (${u.base_rules.join(", ")})`),
        u.base_rules.map((b) => xmlView((app.cat.rule_xml[b] || {}).xml || ""))) : null,
      u.decoder_files.map((f) => el("details", { class: "more-xml" }, el("summary", {}, `Custom decoder: ${f}`), xmlView(app.cat.decoders[f] || ""))),
      u.lists.length ? el("details", { class: "more-xml" }, el("summary", {}, `Lists it uses: ${u.lists.join(", ")}`),
        u.lists.map((l) => el("div", {}, el("p", {}, el("code", { text: `etc/lists/${l}` })), el("pre", { class: "d-log d-list", text: (app.cat.lists[l] || []).join("\n") })))) : null),
    card("False positives and tuning", {}, el("ul", { class: "bullets" }, u.fp.map((x) => el("li", {}, rich(x))))),
    card("How to improve it", {}, el("ul", { class: "bullets" }, u.improve.map((x) => el("li", {}, rich(x))))));

  const right = el("div", { class: "ucside" },
    card("Recent alerts", { side: el("a", { class: "card-link", href: href("alerts", { uc: u.n, ...range }) }, "Search") }, alertsBox),
    card("Test it live", {}, el("p", { class: "fine", text: `Runs on: ${u.where}.` }), el("ol", { class: "steps" }, u.test.map((t) => el("li", {}, withCopy(t))))),
    card("Log sources", {}, el("ul", { class: "sources" }, u.source_detail.map((s) => el("li", {},
      el("strong", { text: s.name }), el("span", {}, rich(s.where)), el("span", { class: "sub" }, rich(s.decoder)))))),
    card(`Regression cases (${u.cases.length})`, {}, el("ul", { class: "cases" }, u.cases.map((c) => el("li", { class: `case case-${c.kind}` },
      el("span", { class: "case-id", text: c.id }), el("span", { class: "case-kind", text: c.kind === "positive" ? "must alert" : "must stay quiet" }),
      el("span", { class: "case-title", text: c.title }))))));
  main.append(el("div", { class: "ucpage" }, left, right));

  (async () => {
    try {
      const d = await api("/api/search", { kind: "alerts", uc: u.n, size: 8, ...range });
      alertsBox.textContent = "";
      alertsBox.append(el("p", { class: "fine", text: `${fmt.plural(d.total, "alert")} in the ${rangeText(range)}.` }));
      if (d.hits.length) {
        alertsBox.append(el("ol", { class: "feedlist" }, d.hits.map((h) => {
          const r = h.doc.rule || {};
          return el("li", {}, el("button", { type: "button", class: "feedrow", onclick: () => openEvent(h, { range }) }, levelBadge(r.level),
            el("span", { class: "feed-what" }, el("span", { class: "feed-desc", text: describe(h.doc) }),
              el("span", { class: "sub", text: `${fmt.stamp(parseTs(h.doc.timestamp))}  ${dig(h.doc, "agent.name") || ""}  rule ${r.id}` }))));
        })));
      } else alertsBox.append(empty("No alerts yet. Follow the test steps and it appears here."));
    } catch (e) {
      alertsBox.textContent = ""; alertsBox.append(errorNotice(e));
    }
  })();
}
