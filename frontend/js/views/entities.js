// Entities: every IP address and every IAM user that shows up in the incidents, and who is tied to whom.
// The map on top is the same preview as in the page of one entity; the table is computed in the browser from the
// shared sample of recent incidents (the same one Analytics uses), so it needs no endpoint of its own.
// A row opens the page of that entity (#/entity/ip/<ip>, #/entity/user/<name>).

import * as data from "../data.js";
import { el, sevBadge, sevClass, sevOfScore, userShort, relTime, fmtNum, fmtPct, plural, attachTip, fullDate } from "../dom.js";
import { emptyBlock } from "../charts.js";
import { panel, pageHead } from "./ui.js";
import { regionMap } from "./regionmap.js";
import { REGION_POINTS } from "../worldmap.js";
import { entityHref, entityLink } from "../links.js";
import * as ex from "../explain.js";

const PAGE = 15;
const LINKED = 3;

// One row per address (with the users behind it) or per user (with the addresses it acted from)
function aggregate(items, kind) {
    const map = new Map();
    items.forEach((i) => {
        const name = kind === "ip" ? i.sourceIPAddress : userShort(i.userIdentity);
        if (!name) return;
        const other = kind === "ip" ? userShort(i.userIdentity) : i.sourceIPAddress;
        const row = map.get(name) || { name, count: 0, maxScore: 0, mitigated: 0, last: 0, others: new Map() };
        row.count++;
        row.maxScore = Math.max(row.maxScore, Number(i.globalScore) || 0);
        if (i.responseTaken) row.mitigated++;
        row.last = Math.max(row.last, Number(i.timestamp) || 0);
        if (other) row.others.set(other, (row.others.get(other) || 0) + 1);
        map.set(name, row);
    });
    return [...map.values()]
        .map((r) => ({ ...r, others: [...r.others.entries()].sort((a, b) => b[1] - a[1]).map(([name]) => name) }))
        .sort((a, b) => b.count - a.count || b.maxScore - a.maxScore);
}

export function mount(root, ctx) {
    const state = { kind: "ip", filter: "", shown: PAGE, items: null, truncated: false };

    const mapCard = panel({
        title: "Regions", sub: "AWS regions the calls were made in, not where the addresses are", minHeight: 260
    });

    // Table card: a switch between addresses and users, a filter, and the rows
    const seg = el("div", { class: "seg", role: "group", "aria-label": "Show" }, [
        el("button", { type: "button", "data-kind": "ip", text: "IP addresses" }),
        el("button", { type: "button", "data-kind": "user", text: "IAM users" })
    ]);
    const filter = el("input", { class: "ent-filter", type: "search", placeholder: "Filter", maxlength: "64", autocomplete: "off", spellcheck: "false", "aria-label": "Filter the list" });
    const title = el("h2");
    const sub = el("p", { class: "sub" });
    const body = el("div", { class: "ent-body" });
    const more = el("div", { class: "ent-more" });
    const foot = el("p", { class: "panel-foot" });
    const tableCard = el("section", { class: "card panel table-card" }, [
        el("header", { class: "panel-head" }, [el("div", {}, [title, sub]), el("div", { class: "panel-tools ent-tools" }, [filter, seg])]),
        body, more, foot
    ]);

    root.append(
        pageHead("Entities", "Every IP address and IAM user in the incidents, and who is tied to whom"),
        el("div", { class: "grid-1" }, [mapCard.root]),
        el("div", { class: "grid-1" }, [tableCard])
    );

    const syncSeg = () => seg.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.kind === state.kind)));
    seg.addEventListener("click", (e) => {
        const button = e.target.closest("button");
        if (!button || button.dataset.kind === state.kind) return;
        state.kind = button.dataset.kind;
        state.shown = PAGE;
        syncSeg();
        draw();
    });
    filter.addEventListener("input", () => { state.filter = filter.value.trim().toLowerCase(); state.shown = PAGE; draw(); });
    syncSeg();

    const linked = (row) => {
        const kind = state.kind === "ip" ? "user" : "ip";
        const nodes = row.others.slice(0, LINKED).map((name) => entityLink(kind, name, { mono: kind === "ip" }));
        const rest = row.others.length - LINKED;
        const out = el("div", { class: "ent-linked" }, nodes);
        if (rest > 0) {
            const chip = el("span", { class: "chip", text: "+" + rest });
            attachTip(chip, row.others.slice(LINKED, LINKED + 12).join(", ") + (rest > 12 ? ", ..." : ""));
            out.append(chip);
        }
        return out;
    };

    function rowNode(row, index) {
        const open = () => { window.location.hash = entityHref(state.kind, row.name); };
        const last = el("td", { class: "nowrap hide-sm", text: relTime(row.last) });
        attachTip(last, fullDate(row.last));
        const sev = sevOfScore(row.maxScore);
        return el("tr", {
            class: "row", tabindex: "0", vars: { "--c": "var(--sev-" + sevClass(sev) + ")", "--i": String(Math.min(index, 14)) },
            "aria-label": (state.kind === "ip" ? "Address " : "User ") + row.name + ", open its page", onclick: open,
            onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } }
        }, [
            el("td", { class: "ent-name" }, [el("b", {}, [entityLink(state.kind, row.name, { mono: state.kind === "ip" })])]),
            el("td", { class: "hide-md" }, [linked(row)]),
            el("td", {}, [el("span", { class: "score", text: fmtNum(row.count) })]),
            el("td", {}, [el("span", { class: "ent-sev" }, [sevBadge(sev), el("span", { class: "score", text: fmtNum(row.maxScore) })])]),
            el("td", { class: "hide-sm", text: fmtPct(row.mitigated / row.count) }),
            last
        ]);
    }

    function draw() {
        syncSeg();
        const isIp = state.kind === "ip";
        title.textContent = isIp ? "IP addresses" : "IAM users";
        if (!state.items) return;
        const all = aggregate(state.items, state.kind);
        const rows = state.filter ? all.filter((r) => r.name.toLowerCase().includes(state.filter) || r.others.some((o) => o.toLowerCase().includes(state.filter))) : all;
        sub.textContent = (isIp ? fmtNum(all.length) + (all.length === 1 ? " address" : " addresses") : plural(all.length, "user")) + " · " + (isIp ? "with the IAM users behind each one" : "with the addresses each one acted from");
        more.replaceChildren();
        if (!all.length) {
            body.replaceChildren(emptyBlock("No incidents in this range"));
            foot.textContent = "";
            return;
        }
        if (!rows.length) {
            body.replaceChildren(emptyBlock("Nothing matches \"" + filter.value.trim() + "\""));
        } else {
            const cls = ["", "hide-md", "", "", "hide-sm", "hide-sm"];
            const labels = [isIp ? "Address" : "User", isIp ? "IAM users" : "Source IPs", "Incidents", "Highest score", "Mitigated", "Last seen"];
            body.replaceChildren(el("div", { class: "table-wrap" }, [el("table", { class: "table ent-table" }, [
                el("thead", {}, [el("tr", {}, labels.map((h, i) => el("th", { scope: "col", class: cls[i], text: h })))]),
                el("tbody", {}, rows.slice(0, state.shown).map(rowNode))
            ])]));
            if (rows.length > state.shown) {
                more.append(el("button", { class: "btn", type: "button", text: "Show more (" + fmtNum(rows.length - state.shown) + " left)", onclick: () => { state.shown += PAGE; draw(); } }));
            }
        }
        foot.textContent = state.truncated
            ? "Based on the latest " + fmtNum(state.items.length) + " incidents of this range; there are more, so counts are an estimate."
            : "Based on all " + fmtNum(state.items.length) + " incidents of this range.";
    }

    let run = 0;
    async function refresh(soft = false) {
        const mine = ++run;
        const sampled = () => data.sample(ctx.days());
        if (!soft) {
            body.replaceChildren(el("div", { class: "skel ent-skel", vars: { "--h": "220px" } }));
            more.replaceChildren();
            foot.textContent = "";
            title.textContent = state.kind === "ip" ? "IP addresses" : "IAM users";
            sub.textContent = "";
        }
        mapCard.load(sampled, (res) => {
            if (!res.items.length) { mapCard.empty("No incidents in this range"); return; }
            mapCard.show(regionMap(res.items));
            mapCard.explain(ex.regionExplain(res.items, (r) => (REGION_POINTS[r] ? REGION_POINTS[r][2] : r)));
        }, { soft });
        try {
            const res = await sampled();
            if (mine !== run) return;
            state.items = res.items;
            state.truncated = res.truncated;
            draw();
        } catch (err) {
            if (mine !== run || soft) return;
            body.replaceChildren(el("div", { class: "error-box" }, [
                el("p", { text: "Could not load the entities. " + (err && err.message ? err.message : "") }),
                el("button", { class: "btn", type: "button", text: "Retry", onclick: () => refresh() })
            ]));
        }
    }

    refresh();
    return { refresh: (soft) => refresh(soft === true), destroy() { run++; } };
}
