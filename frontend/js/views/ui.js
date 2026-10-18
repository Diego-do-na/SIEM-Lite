// Shared building blocks for the views: cards with loading, error and empty states,
// and the incident table used by Overview and Incidents.

import { el, icon, ICONS, sevBadge, sevClass, relTime, relTimeShort, fullDate, userShort, techName, attachTip, fmtNum } from "../dom.js";
import { emptyBlock } from "../charts.js";

// A card whose body can be loading, failed (with Retry) or filled, independent of the others:
// one failing report must not hide the rest of the page
export function panel({ title, sub, className = "", minHeight = 200, action }) {
    const subNode = sub ? el("p", { class: "sub", text: sub }) : null;
    const body = el("div", { class: "panel-body" });
    const foot = el("p", { class: "panel-foot" });
    const root = el("section", { class: "card panel " + className }, [
        el("header", { class: "panel-head" }, [el("div", {}, [el("h2", { text: title }), subNode]), action || null]),
        body,
        foot
    ]);
    const api = {
        root, body, foot,
        loading() { body.replaceChildren(el("div", { class: "skel", vars: { "--h": minHeight + "px" } })); },
        show(node) { body.replaceChildren(node); },
        empty(text) { body.replaceChildren(emptyBlock(text)); },
        setSub(text) { if (subNode) subNode.textContent = text; },
        note(text) { foot.textContent = text || ""; },
        error(err, retry) {
            body.replaceChildren(el("div", { class: "error-box" }, [
                el("p", { text: "Could not load this section. " + (err && err.message ? err.message : "") }),
                retry ? el("button", { class: "btn", type: "button", text: "Retry", onclick: retry }) : null
            ]));
        },
        // loader() -> data, render(data) -> node. A newer call makes an older, slower one a no-op.
        // soft: keep what is on screen while the new data loads (used by the automatic refresh)
        async load(loader, render, { soft = false } = {}) {
            const run = (api._run = (api._run || 0) + 1);
            if (!soft) api.loading();
            try {
                const data = await loader();
                if (run !== api._run) return;
                render(data);
            } catch (err) {
                if (run !== api._run) return;
                if (soft) return;
                api.error(err, () => api.load(loader, render));
            }
        }
    };
    return api;
}

// A small figure with a caption, used in the strip at the top of Analytics
export function statCard(label, value, sub) {
    return el("div", { class: "card kpi stat" }, [
        el("div", { class: "label", text: label }),
        el("div", { class: "value", text: value }),
        el("p", { class: "delta", text: sub || "" })
    ]);
}

export function pageHead(title, sub, right) {
    return el("div", { class: "page-head" }, [
        el("div", {}, [el("h1", { text: title }), sub ? el("p", { class: "sub", text: sub }) : null]),
        right || null
    ]);
}

function responseCell(item) {
    return el("span", { class: "resp" + (item.responseTaken ? " on" : "") }, [
        item.responseTaken ? icon(ICONS.shieldCheck) : icon(ICONS.minus),
        item.responseTaken ? "Mitigated" : "None"
    ]);
}

// A technique id as a button: it opens the ATT&CK card. Inside a table row it must not also open the incident
export function techChip(id, { showName = false } = {}) {
    const name = techName(id);
    const button = el("button", {
        class: "chip tech-btn", type: "button", "aria-haspopup": "dialog",
        title: (name ? name + ". " : "") + "Open the technique card",
        onclick: (e) => { e.stopPropagation(); import("../mitrecard.js").then((m) => m.openTechnique(id, button)); },
        onkeydown: (e) => e.stopPropagation()
    }, [id, showName && name ? el("span", { class: "chip-name", text: name }) : null]);
    return button;
}

function techniqueChips(list) {
    const items = list || [];
    const shown = items.slice(0, 2).map((t) => techChip(t));
    if (items.length > 2) shown.push(el("span", { class: "chip", text: "+" + (items.length - 2) }));
    return shown;
}

const COLUMNS = [
    ["Severity", ""], ["Time", ""], ["IAM user", ""], ["Source IP", "hide-md"], ["Score", ""], ["MITRE technique", "hide-sm"], ["Automated response", "hide-md"], ["", "hide-sm"]
];

export function incidentTable({ onOpen }) {
    const tbody = el("tbody");
    const head = el("tr", {}, COLUMNS.map(([name, cls]) => el("th", { class: cls, scope: "col", text: name })));
    const root = el("div", { class: "table-wrap" }, [el("table", { class: "table" }, [el("thead", {}, [head]), tbody])]);

    function message(node) {
        tbody.replaceChildren(el("tr", {}, [el("td", { colspan: String(COLUMNS.length) }, [node])]));
    }

    // Rows already shown, so a refresh can highlight only the ones that just arrived
    const seen = new Set();
    const keyOf = (item) => item.severity + "/" + item.timestamp + "/" + (item.incidentId || "");

    function row(item, index, fresh, animate) {
        const open = () => onOpen(item.severity, item.timestamp);
        const technique = (item.mitreTechniques || []).map(techName).find(Boolean) || "";
        const timeCell = el("td", { class: "nowrap" }, [el("span", { class: "t-long", text: relTime(item.timestamp) }), el("span", { class: "t-short", text: relTimeShort(item.timestamp) })]);
        attachTip(timeCell, fullDate(item.timestamp));
        return el("tr", {
            class: "row" + (fresh ? " fresh" : "") + (animate ? " enter" : ""), tabindex: "0",
            vars: { "--c": "var(--sev-" + sevClass(item.severity) + ")", "--i": String(Math.min(index, 14)) },
            "aria-label": item.severity + " incident, open details", onclick: open,
            onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } }
        }, [
            el("td", {}, [sevBadge(item.severity)]),
            timeCell,
            el("td", { class: "who-cell" }, [el("b", { text: userShort(item.userIdentity) }), technique ? el("small", { text: technique }) : null]),
            el("td", { class: "hide-md mono", text: item.sourceIPAddress || "" }),
            el("td", {}, [el("span", { class: "score", text: fmtNum(item.globalScore) })]),
            el("td", { class: "hide-sm" }, techniqueChips(item.mitreTechniques)),
            el("td", { class: "hide-md" }, [responseCell(item)]),
            el("td", { class: "chev hide-sm" }, [icon(ICONS.chevronRight)])
        ]);
    }

    return {
        root,
        loading(rows = 5) {
            tbody.replaceChildren(...Array.from({ length: rows }, () =>
                el("tr", {}, [el("td", { colspan: String(COLUMNS.length) }, [el("div", { class: "skel", vars: { "--h": "28px" } })])])));
        },
        empty(text) { message(emptyBlock(text)); },
        error(err, retry) {
            message(el("div", { class: "error-box" }, [
                el("p", { text: "Could not load incidents. " + (err && err.message ? err.message : "") }),
                retry ? el("button", { class: "btn", type: "button", text: "Retry", onclick: retry }) : null
            ]));
        },
        resetSeen() { seen.clear(); },
        // soft: a refresh of rows already on screen. New rows are highlighted instead of animating all of them in
        setRows(items, append, soft = false) {
            const known = seen.size > 0;
            if (!append) tbody.replaceChildren();
            items.forEach((item, index) => {
                const key = keyOf(item);
                const fresh = soft && known && !seen.has(key);
                seen.add(key);
                tbody.appendChild(row(item, index, fresh, !soft));
            });
        }
    };
}
