// ATT&CK coverage matrix: the tactics of the cloud matrix as columns, and the techniques SIEM Lite has a rule for
// lit inside them. The empty columns are on purpose: they show what the detection does not cover yet.

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
    const columns = TACTICS.map((tactic) => {
        const own = covered.filter((t) => t.tactic === tactic.name);
        const total = own.reduce((n, t) => n + (counts[t.id] || 0), 0);
        return el("div", { class: "mx-col" + (own.length ? " on" : "") }, [
            el("header", {}, [el("b", { text: tactic.name }), el("small", { text: tactic.id + (own.length ? " · " + fmtNum(total) : "") })]),
            ...(own.length ? own.map((t) => techniqueCell(t, counts[t.id] || 0, peak)) : [el("div", { class: "mx-empty", text: "No rule yet" })])
        ]);
    });
    return el("div", {}, [
        el("div", { class: "mx-scroll" }, [el("div", { class: "mx" }, columns)]),
        el("p", { class: "mx-legend", text: plural(covered.length, "technique") + " covered across " + litTactics.size + " of " + TACTICS.length + " tactics. The number on each technique is incidents in this range; a column that says \"No rule yet\" is not detected today." })
    ]);
}
