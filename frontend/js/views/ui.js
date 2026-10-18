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
        // loader() -> data, render(data) -> node. A newer call makes an older, slower one a no-op
        async load(loader, render) {
            const run = (api._run = (api._run || 0) + 1);
            api.loading();
            try {
                const data = await loader();
                if (run !== api._run) return;
                render(data);
            } catch (err) {
                if (run !== api._run) return;
                api.error(err, () => api.load(loader, render));
            }
        }
    };
    return api;
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

function techniqueChips(list) {
    const items = list || [];
    const shown = items.slice(0, 2).map((t) => el("span", { class: "chip", text: t }));
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

    function row(item) {
        const open = () => onOpen(item.severity, item.timestamp);
        const technique = (item.mitreTechniques || []).map(techName).find(Boolean) || "";
        const timeCell = el("td", { class: "nowrap" }, [el("span", { class: "t-long", text: relTime(item.timestamp) }), el("span", { class: "t-short", text: relTimeShort(item.timestamp) })]);
        attachTip(timeCell, fullDate(item.timestamp));
        return el("tr", {
            class: "row", tabindex: "0", vars: { "--c": "var(--sev-" + sevClass(item.severity) + ")" },
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
        setRows(items, append) {
            if (!append) tbody.replaceChildren();
            items.forEach((item) => tbody.appendChild(row(item)));
        }
    };
}
