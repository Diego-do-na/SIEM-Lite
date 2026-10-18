// Incidents: the full list with filters and keyset pagination. Filters go to the API as is;
// the API validates them again, this form only makes the common cases easy.

import * as data from "../data.js";
import { el, icon, ICONS, fmtNum } from "../dom.js";
import { pageHead, incidentTable } from "./ui.js";

const dayStart = (value) => Math.floor(new Date(value + "T00:00:00Z").getTime() / 1000);

export function mount(root, ctx) {
    let cursor = null;
    let shown = 0;
    let pages = 0;
    let run = 0;

    const field = (label, control) => el("label", { class: "field" }, [label, control]);
    // The arrow is an icon of our own: the native one sits against the border and cannot be moved
    const select = (control) => el("span", { class: "select-wrap" }, [control, icon(ICONS.chevronDown)]);
    const severity = el("select", { name: "severity" }, [["", "All"], ["CRITICAL", "Critical"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["LOW", "Low"]].map(([v, t]) => el("option", { value: v, text: t })));
    const from = el("input", { type: "date", name: "from" });
    const to = el("input", { type: "date", name: "to" });
    const ip = el("input", { type: "text", name: "ip", maxlength: "64", placeholder: "203.0.113." });
    const user = el("input", { type: "text", name: "user", maxlength: "64", placeholder: "svc-deploy" });
    const technique = el("input", { type: "text", name: "technique", maxlength: "64", placeholder: "T1562.008" });

    const summary = el("span", { class: "summary", text: "No filters applied" });
    const toggle = el("button", { class: "filters-head", type: "button", "aria-expanded": "true", "aria-controls": "filters-body" }, [icon(ICONS.filter), el("b", { text: "Filters" }), summary, icon(ICONS.chevronDown)]);
    const form = el("form", { class: "filters-body", id: "filters-body" }, [
        el("div", { class: "filters-grid" }, [field("Severity", select(severity)), field("From", from), field("To", to), field("Source IP", ip), field("IAM user", user), field("Technique", technique)]),
        el("div", { class: "filters-actions" }, [
            el("button", { class: "btn btn-primary", type: "submit", text: "Search" }),
            el("button", { class: "btn", type: "button", id: "reset", text: "Clear" })
        ])
    ]);
    const filtersCard = el("section", { class: "card", id: "filters-card" }, [toggle, form]);

    const table = incidentTable({ onOpen: ctx.openIncident });
    const count = el("span", { text: "" });
    const fresh = el("button", { class: "link-btn", type: "button", text: "New incidents arrived. Reload the list", hidden: true });
    const more = el("button", { class: "btn", type: "button", text: "Load more", hidden: true });
    const tableCard = el("section", { class: "card table-card" }, [
        el("div", { class: "panel-head" }, [el("div", {}, [el("h2", { text: "All incidents" }), el("p", { class: "sub", text: "Newest first · select a row for details" })])]),
        table.root,
        el("div", { class: "table-foot" }, [el("span", { class: "foot-left" }, [count, fresh]), more])
    ]);
    root.append(pageHead("Incidents", "Every detection, with the filters of the API"), filtersCard, tableCard);

    // Links such as #/incidents?technique=T1485 arrive with filters already set
    const fromLink = ctx.query || new URLSearchParams();
    [["severity", severity], ["technique", technique], ["user", user], ["ip", ip]].forEach(([name, input]) => {
        const v = fromLink.get(name);
        if (v) input.value = name === "severity" ? v.toUpperCase() : v.slice(0, 64);
    });
    if (severity.value !== (fromLink.get("severity") || "").toUpperCase() && fromLink.get("severity")) severity.value = "";

    // What the list on screen was asked with. Typing in the form changes nothing until Search is pressed,
    // and the automatic refresh keeps using these, not whatever is half typed
    function snapshot() {
        const p = new URLSearchParams({ limit: "25" });
        [["severity", severity], ["ip", ip], ["user", user], ["technique", technique]].forEach(([name, input]) => {
            const v = input.value.trim();
            if (v) p.set(name, v);
        });
        if (from.value) p.set("from", String(dayStart(from.value)));
        if (to.value) p.set("to", String(dayStart(to.value) + 86399));
        return p;
    }
    let applied = snapshot();

    function activeCount() {
        return [severity, from, to, ip, user, technique].filter((i) => i.value.trim()).length;
    }

    // append: next page. soft: the automatic refresh, which keeps the rows on screen and highlights new ones
    async function load(append, soft = false) {
        // With more than the first page open, replacing the list would throw away the scroll position
        if (soft && pages > 1) {
            fresh.hidden = false;
            return;
        }
        const myRun = ++run;
        if (!append && !soft) {
            applied = snapshot();
            cursor = null;
            shown = 0;
            pages = 0;
            table.resetSeen();
            table.loading(6);
            more.hidden = true;
            count.textContent = "";
        }
        fresh.hidden = true;
        more.disabled = true;
        const n = activeCount();
        if (!soft) summary.textContent = n ? n + " filter" + (n === 1 ? "" : "s") + " applied" : "No filters applied";
        try {
            const p = new URLSearchParams(applied);
            if (append && cursor) p.set("cursor", cursor);
            const res = await data.incidents(p);
            if (myRun !== run) return;
            if (!append) {
                shown = 0;
                pages = 0;
            }
            if (!append && !res.items.length) {
                table.empty(applied.has("severity") || applied.has("ip") || applied.has("user") || applied.has("technique") || applied.has("from") || applied.has("to") ? "No incidents match these filters" : "No incidents yet");
            } else {
                table.setRows(res.items, append, soft);
            }
            shown += res.items.length;
            pages++;
            cursor = res.nextCursor;
            more.hidden = !cursor;
            count.textContent = shown ? "Showing " + fmtNum(shown) + (cursor ? "+" : "") + " incidents" : "";
        } catch (err) {
            if (myRun !== run) return;
            if (soft) return;
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
    fresh.addEventListener("click", () => load(false));

    load(false);
    return { refresh: (soft) => load(false, soft === true), destroy() { run++; } };
}
