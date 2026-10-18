// Incidents: the full list with filters and keyset pagination. Filters go to the API as is;
// the API validates them again, this form only makes the common cases easy.

import * as data from "../data.js";
import { el, icon, ICONS, fmtNum } from "../dom.js";
import { pageHead, incidentTable } from "./ui.js";

const dayStart = (value) => Math.floor(new Date(value + "T00:00:00Z").getTime() / 1000);

export function mount(root, ctx) {
    let cursor = null;
    let shown = 0;
    let run = 0;

    const field = (label, control) => el("label", { class: "field" }, [label, control]);
    const severity = el("select", { name: "severity" }, [["", "All"], ["CRITICAL", "Critical"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["LOW", "Low"]].map(([v, t]) => el("option", { value: v, text: t })));
    const from = el("input", { type: "date", name: "from" });
    const to = el("input", { type: "date", name: "to" });
    const ip = el("input", { type: "text", name: "ip", maxlength: "64", placeholder: "203.0.113." });
    const user = el("input", { type: "text", name: "user", maxlength: "64", placeholder: "svc-deploy" });
    const technique = el("input", { type: "text", name: "technique", maxlength: "64", placeholder: "T1562.008" });

    const summary = el("span", { class: "summary", text: "No filters applied" });
    const toggle = el("button", { class: "filters-head", type: "button", "aria-expanded": "true", "aria-controls": "filters-body" }, [icon(ICONS.filter), el("b", { text: "Filters" }), summary, icon(ICONS.chevronDown)]);
    const form = el("form", { class: "filters-body", id: "filters-body" }, [
        el("div", { class: "filters-grid" }, [field("Severity", severity), field("From", from), field("To", to), field("Source IP", ip), field("IAM user", user), field("Technique", technique)]),
        el("div", { class: "filters-actions" }, [
            el("button", { class: "btn btn-primary", type: "submit", text: "Search" }),
            el("button", { class: "btn", type: "button", id: "reset", text: "Clear" })
        ])
    ]);
    const filtersCard = el("section", { class: "card", id: "filters-card" }, [toggle, form]);

    const table = incidentTable({ onOpen: ctx.openIncident });
    const count = el("span", { text: "" });
    const more = el("button", { class: "btn", type: "button", text: "Load more", hidden: true });
    const tableCard = el("section", { class: "card table-card" }, [
        el("div", { class: "panel-head" }, [el("div", {}, [el("h2", { text: "All incidents" }), el("p", { class: "sub", text: "Newest first · select a row for details" })])]),
        table.root,
        el("div", { class: "table-foot" }, [count, more])
    ]);
    root.append(pageHead("Incidents", "Every detection, with the filters of the API"), filtersCard, tableCard);

    function params(append) {
        const p = new URLSearchParams({ limit: "25" });
        [["severity", severity], ["ip", ip], ["user", user], ["technique", technique]].forEach(([name, input]) => {
            const v = input.value.trim();
            if (v) p.set(name, v);
        });
        if (from.value) p.set("from", String(dayStart(from.value)));
        if (to.value) p.set("to", String(dayStart(to.value) + 86399));
        if (append && cursor) p.set("cursor", cursor);
        return p;
    }

    function activeCount() {
        return [severity, from, to, ip, user, technique].filter((i) => i.value.trim()).length;
    }

    async function load(append) {
        const myRun = ++run;
        if (!append) {
            cursor = null;
            shown = 0;
            table.loading(6);
            more.hidden = true;
            count.textContent = "";
        }
        more.disabled = true;
        const n = activeCount();
        summary.textContent = n ? n + " filter" + (n === 1 ? "" : "s") + " applied" : "No filters applied";
        try {
            const res = await data.incidents(params(append));
            if (myRun !== run) return;
            if (!append && !res.items.length) {
                table.empty(n ? "No incidents match these filters" : "No incidents yet");
            } else {
                table.setRows(res.items, append);
            }
            shown += res.items.length;
            cursor = res.nextCursor;
            more.hidden = !cursor;
            count.textContent = shown ? "Showing " + fmtNum(shown) + (cursor ? "+" : "") + " incidents" : "";
        } catch (err) {
            if (myRun !== run) return;
            if (append) count.textContent = err.message;
            else table.error(err, () => load(false));
        } finally {
            more.disabled = false;
        }
    }

    toggle.addEventListener("click", () => {
        const open = toggle.getAttribute("aria-expanded") === "true";
        toggle.setAttribute("aria-expanded", String(!open));
        form.hidden = open;
    });
    form.addEventListener("submit", (e) => { e.preventDefault(); load(false); });
    form.querySelector("#reset").addEventListener("click", () => { form.reset(); load(false); });
    more.addEventListener("click", () => load(true));

    load(false);
    return { refresh: () => load(false), destroy() { run++; } };
}
