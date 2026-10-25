// ATT&CK coverage matrix: one column for each tactic SIEM Lite has a rule for, with its techniques inside.
// The tactics without a rule are not drawn as empty columns: they are named in plain text below, so the gaps stay visible.

import { el, fmtNum, plural } from "../dom.js";
import { TACTICS, TECHNIQUES } from "../mitre.js";

function techniqueCell(t, count, peak) {
    const button = el("button", {
        class: "mx-tech" + (count ? " hot" : ""), type: "button", "aria-haspopup": "dialog",
        vars: { "--a": String(count ? 0.14 + 0.5 * (count / Math.max(1, peak)) : 0) },
        title: t.name + ". Open the technique card",
        onclick: () => import("../mitrecard.js").then((m) => m.openTechnique(t.id, button))
    }, [
        el("span", { class: "mx-id", text: t.id }),
        el("span", { class: "mx-name", text: t.name }),
        el("span", { class: "mx-count", text: count ? fmtNum(count) : "0" })
    ]);
    return button;
}

// counts: { "T1485": 12, ... } incidents per technique in the range
export function attackMatrix(counts) {
    const peak = Math.max(1, ...Object.values(counts));
    const covered = Object.values(TECHNIQUES);
    const litTactics = new Set(covered.map((t) => t.tactic));
    const withRules = TACTICS.filter((tactic) => litTactics.has(tactic.name));
    const gaps = TACTICS.filter((tactic) => !litTactics.has(tactic.name));
    const columns = withRules.map((tactic) => {
        const own = covered.filter((t) => t.tactic === tactic.name);
        const total = own.reduce((n, t) => n + (counts[t.id] || 0), 0);
        return el("div", { class: "mx-col on" }, [
            el("header", {}, [el("b", { text: tactic.name }), el("small", { text: tactic.id + " · " + fmtNum(total) })]),
            ...own.map((t) => techniqueCell(t, counts[t.id] || 0, peak))
        ]);
    });
    return el("div", {}, [
        el("div", { class: "mx-scroll" }, [el("div", { class: "mx", vars: { "--cols": String(columns.length) } }, columns)]),
        el("p", { class: "mx-legend", text: plural(covered.length, "technique") + " covered across " + litTactics.size + " of " + TACTICS.length + " tactics. The number on each technique is incidents in this range." }),
        gaps.length ? el("div", { class: "mx-gaps" }, [
            el("h4", { text: "Not covered yet" }),
            el("p", { text: gaps.map((g) => g.name).join(", ") + ". SIEM Lite has no detection rule for these " + gaps.length + " tactics today, so an attacker at those stages would not raise an incident." })
        ]) : null
    ]);
}
