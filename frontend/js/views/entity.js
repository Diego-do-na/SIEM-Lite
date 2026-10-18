// The page of one entity: an IP address (#/entity/ip/<ip>) or an IAM user (#/entity/user/<name>).
// Everything an analyst asks next after seeing it in a table: how often, since when, how serious, with whom, doing what.
// All of it is computed from the incidents the API already returns, filtered to the entity.

import * as data from "../data.js";
import { el, icon, ICONS, sevBadge, sevClass, sevOfScore, userShort, shortDate, clock, fmtNum, fmtPct, plural, techName } from "../dom.js";
import { rankedBars, scoreTimeline } from "../charts.js";
import { panel, incidentTable } from "./ui.js";
import { regionMap } from "./regionmap.js";
import { REGION_POINTS } from "../worldmap.js";
import { entityLink, parseEntity } from "../links.js";
import { techChip } from "../techchip.js";
import * as ex from "../explain.js";

const sevName = (s) => s.charAt(0) + s.slice(1).toLowerCase();
const stamp = (t) => shortDate(new Date(Number(t) * 1000)) + " · " + clock(t) + " UTC";

// Who or what the entity is tied to: for an address, its users; for a user, its addresses
function related(kind, items) {
    const map = new Map();
    items.forEach((i) => {
        const name = kind === "ip" ? userShort(i.userIdentity) : i.sourceIPAddress;
        if (!name) return;
        const row = map.get(name) || { name, count: 0, maxScore: 0 };
        row.count++;
        row.maxScore = Math.max(row.maxScore, Number(i.globalScore) || 0);
        map.set(name, row);
    });
    return [...map.values()].sort((a, b) => b.count - a.count || b.maxScore - a.maxScore);
}

function techniques(items) {
    const map = new Map();
    items.forEach((i) => (i.mitreTechniques || []).forEach((t) => map.set(t, (map.get(t) || 0) + 1)));
    return [...map.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
}

// The sentence under the title. Plain rules over the numbers, so it can be checked against the cards
function lede(kind, value, items, rel, truncated) {
    const sorted = items.slice().sort((a, b) => a.timestamp - b.timestamp);
    const peak = items.reduce((a, b) => ((Number(b.globalScore) || 0) > (Number(a.globalScore) || 0) ? b : a));
    const mitigated = items.filter((i) => i.responseTaken).length;
    const what = kind === "ip" ? "This address" : value;
    const parts = [
        what + " appears in " + plural(items.length, "incident") + (truncated ? " (the latest ones; there are more)" : "") + ", from " + shortDate(new Date(Number(sorted[0].timestamp) * 1000)) + " to " + shortDate(new Date(Number(sorted[sorted.length - 1].timestamp) * 1000)) + ".",
        "The highest score is " + fmtNum(peak.globalScore) + " (" + sevName(peak.severity) + ")."
    ];
    if (rel.length > 1) parts.push(kind === "ip" ? "It was used by " + rel.length + " different IAM users." : "It acted from " + rel.length + " different addresses.");
    parts.push(mitigated ? plural(mitigated, "incident") + " " + (mitigated === 1 ? "was" : "were") + " mitigated automatically." : "None was mitigated automatically.");
    return parts.join(" ");
}

function hero(kind, value, items, rel, truncated) {
    const peak = items.reduce((a, b) => ((Number(b.globalScore) || 0) > (Number(a.globalScore) || 0) ? b : a));
    const sorted = items.slice().sort((a, b) => a.timestamp - b.timestamp);
    const mitigated = items.filter((i) => i.responseTaken).length;
    const color = "var(--sev-" + sevClass(peak.severity) + ")";
    const facts = [
        ["Incidents", fmtNum(items.length) + (truncated ? "+" : "")],
        ["Highest score", fmtNum(peak.globalScore)],
        ["First seen", stamp(sorted[0].timestamp)],
        ["Last seen", stamp(sorted[sorted.length - 1].timestamp)],
        ["Mitigated", fmtPct(mitigated / items.length)],
        [kind === "ip" ? "IAM users" : "Addresses", fmtNum(rel.length)]
    ];
    return el("section", { class: "card ent-hero", vars: { "--c": color } }, [
        el("div", { class: "ent-main" }, [
            el("div", { class: "inc-eyebrow" }, [el("span", { class: "pill", text: kind === "ip" ? "IP address" : "IAM user" }), sevBadge(peak.severity)]),
            el("h1", { class: kind === "ip" ? "mono" : "", text: value }),
            el("p", { class: "inc-lede", text: lede(kind, value, items, rel, truncated) }),
            el("div", { class: "ent-actions" }, [
                el("a", { class: "btn", href: "#/incidents?" + (kind === "ip" ? "ip" : "user") + "=" + encodeURIComponent(value), text: "Open in Incidents" })
            ])
        ]),
        el("dl", { class: "ent-facts" }, facts.map(([k, v]) => el("div", {}, [el("dt", { text: k }), el("dd", { text: v })])))
    ]);
}

function relatedList(kind, rows) {
    const peak = Math.max(1, ...rows.map((r) => r.count));
    return el("ul", { class: "rel-list" }, rows.map((r, index) => el("li", {}, [
        el("div", { class: "rel-top" }, [entityLink(kind === "ip" ? "user" : "ip", r.name, { mono: kind !== "ip" }), el("span", { class: "rel-n", text: plural(r.count, "incident") })]),
        el("div", { class: "bar-track" }, [el("div", { class: "bar-fill", vars: { "--w": Math.max(2, (r.count / peak) * 100) + "%", "--i": String(index) } })]),
        el("small", { text: "highest score " + fmtNum(r.maxScore) + " · " + sevName(sevOfScore(r.maxScore)) })
    ])));
}

export function mount(root, ctx) {
    const entity = parseEntity(ctx.param);
    const head = el("div", { class: "inc-top" }, [
        el("a", { class: "back", href: "#/entities", onclick: (e) => { if (ctx.canGoBack()) { e.preventDefault(); history.back(); } } }, [icon(ICONS.chevronLeft), "Back"])
    ]);
    const body = el("div", { class: "inc-body" });
    root.append(head, body);
    let run = 0;

    const message = (text, ...actions) => body.replaceChildren(el("div", { class: "card panel" }, [el("div", { class: "error-box" }, [el("p", { text }), ...actions])]));

    if (!entity) {
        message("This link is not valid. An entity is an IP address or an IAM user.", el("a", { class: "btn", href: "#/incidents", text: "Go to incidents" }));
        return { refresh() {}, destroy() {} };
    }
    const { kind, value } = entity;
    document.title = value + " · SIEM Lite";

    const timelineCard = panel({ title: "Risk over time", sub: "Score of each incident · select a dot to open it", minHeight: 240 });
    const techCard = panel({ title: "Techniques", sub: "What this " + (kind === "ip" ? "address" : "identity") + " was doing", minHeight: 200, className: "top" });
    const relatedCard = panel({ title: kind === "ip" ? "IAM users behind this address" : "Addresses this user acted from", sub: kind === "ip" ? "Identities whose credentials made calls from it" : "Where the calls came from", minHeight: 200, className: "top" });
    const mapCard = panel({ title: "Regions", sub: kind === "ip" ? "AWS regions this address made calls to" : "AWS regions this user made calls in", minHeight: 200, action: el("span", { class: "pill", title: "Region per incident is part of the 1.1 API. Until then it shows in demo data only.", text: "Preview" }) });
    const table = incidentTable({ onOpen: ctx.openIncident });
    const tableCard = el("section", { class: "card panel table-card" }, [
        el("header", { class: "panel-head" }, [el("div", {}, [el("h2", { text: "Incidents" }), el("p", { class: "sub", text: "Newest first · select a row for details" })])]),
        table.root
    ]);
    const heroSlot = el("div", {});

    // Wide chart first, then the two short lists side by side, then the map and the rows
    const layout = () => body.replaceChildren(
        heroSlot,
        el("div", { class: "grid-1" }, [timelineCard.root]),
        el("div", { class: "grid-2" }, [techCard.root, relatedCard.root]),
        el("div", { class: "grid-1" }, [mapCard.root]),
        tableCard
    );

    async function load(soft = false) {
        const mine = ++run;
        if (!soft) {
            heroSlot.replaceChildren(el("div", { class: "skel", vars: { "--h": "170px" } }));
            layout();
            [timelineCard, techCard, relatedCard, mapCard].forEach((c) => c.loading());
            table.loading(4);
        }
        try {
            const res = await data.entity(kind, value);
            if (mine !== run) return;
            if (!res.items.length) {
                message("No incidents found for " + value + ". It may be misspelled, or older than the incidents the API returns.", el("a", { class: "btn", href: "#/incidents", text: "Go to incidents" }));
                return;
            }
            if (!body.contains(heroSlot)) layout();
            const items = res.items.slice().sort((a, b) => b.timestamp - a.timestamp);
            const rel = related(kind, items);
            const techs = techniques(items);
            heroSlot.replaceChildren(hero(kind, value, items, rel, res.truncated));

            timelineCard.show(scoreTimeline(items, "Risk score of each incident over time", ctx.openIncident));
            timelineCard.explain(ex.timelineExplain(items));

            techCard.show(el("div", { class: "ent-techs" }, [
                rankedBars(techs.map((t) => ({ label: t.label, who: techName(t.label), value: t.value }))),
                el("div", { class: "inc-chips" }, techs.map((t) => techChip(t.label, { showName: true })))
            ]));
            techCard.explain(ex.techniqueExplain(techs));

            relatedCard.show(relatedList(kind, rel));
            relatedCard.explain(ex.relatedExplain(kind, rel));

            mapCard.show(regionMap(items));
            mapCard.explain(ex.regionExplain(items, (r) => (REGION_POINTS[r] ? REGION_POINTS[r][2] : r)));

            table.setRows(items.slice(0, 50), false, soft);
            tableCard.querySelector(".sub").textContent = items.length > 50 ? "Newest 50 of " + fmtNum(items.length) + (res.truncated ? "+" : "") + " · select a row for details" : "Newest first · select a row for details";
        } catch (err) {
            if (mine !== run || soft) return;
            body.replaceChildren(el("div", { class: "card panel" }, [el("div", { class: "error-box" }, [
                el("p", { text: "Could not load this page. " + (err && err.message ? err.message : "") }),
                el("button", { class: "btn", type: "button", text: "Retry", onclick: () => load() })
            ])]));
        }
    }

    load();
    return { refresh: (soft) => load(soft === true), destroy() { run++; } };
}
