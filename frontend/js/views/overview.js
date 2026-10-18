// Overview: the few things worth seeing first. KPIs, the trend, top techniques, latest incidents.

import * as data from "../data.js";
import { el, SEVERITIES, sevClass, fmtNum, shortDate, techName } from "../dom.js";
import { stackedArea, donut, legend } from "../charts.js";
import { panel, pageHead, incidentTable } from "./ui.js";

function delta(now, before, days) {
    if (before === null || before === undefined) return el("p", { class: "delta", text: "Previous period not available for this range" });
    if (before === 0) return el("p", { class: "delta", text: now === 0 ? "No change vs previous " + days + "d" : "New vs previous " + days + "d" });
    const pct = ((now - before) / before) * 100;
    if (Math.abs(pct) < 0.05) return el("p", { class: "delta", text: "No change vs previous " + days + "d" });
    const up = pct > 0;
    return el("p", { class: "delta" }, [
        el("b", { class: up ? "up" : "down", text: (up ? "↑ " : "↓ ") + Math.abs(pct).toFixed(1) + "%" }),
        " vs previous " + days + "d"
    ]);
}

export function mount(root, ctx) {
    const kpiRow = el("section", { class: "grid-kpi", "aria-label": "Incident totals" });
    const trendCard = panel({ title: "Incidents over time", sub: "Daily detections by severity · UTC", minHeight: 250 });
    const mitreCard = panel({ title: "Top MITRE ATT&CK techniques", sub: "Incidents per technique", minHeight: 250 });
    const latestCard = el("section", { class: "card panel table-card" });
    const table = incidentTable({ onOpen: ctx.openIncident });
    const latestFoot = el("p", { class: "panel-foot" });
    latestCard.append(
        el("header", { class: "panel-head" }, [
            el("div", {}, [el("h2", { text: "Latest incidents" }), el("p", { class: "sub", text: "Most recent detections · all severities" })]),
            el("a", { href: "#/incidents", text: "View all incidents" })
        ]),
        table.root, latestFoot
    );
    const sub = el("p", { class: "sub" });
    const status = el("span", { class: "status" }, [el("i", { class: "dot" }), el("span", { text: "Checking..." })]);
    root.append(pageHead("Security overview", null, status), kpiRow, el("div", { class: "grid-2" }, [trendCard.root, mitreCard.root]), latestCard);
    root.querySelector(".page-head > div").appendChild(sub);

    function kpiSkeleton() {
        kpiRow.replaceChildren(...Array.from({ length: 5 }, () => el("div", { class: "card kpi" }, [el("div", { class: "skel", vars: { "--h": "74px" } })])));
    }

    function renderKpis(summary, days) {
        const cards = [["Total incidents", "total", null], ...SEVERITIES.map((s) => [s.charAt(0) + s.slice(1).toLowerCase(), s, s])];
        kpiRow.replaceChildren(...cards.map(([label, key, sev]) => el("div", { class: "card kpi", vars: sev ? { "--c": "var(--sev-" + sevClass(sev) + ")" } : {} }, [
            el("div", { class: "label" }, [sev ? el("i", { class: "sev-dot", vars: { "--c": "var(--sev-" + sevClass(sev) + ")" } }) : null, label]),
            el("div", { class: "value", text: fmtNum(summary.now[key]) }),
            delta(summary.now[key], summary.before ? summary.before[key] : null, days)
        ])));
    }

    let run = 0;
    async function refresh() {
        const myRun = ++run;
        const days = ctx.days();
        kpiSkeleton();
        trendCard.loading();
        mitreCard.loading();
        table.loading(6);

        data.health().then((h) => {
            const ok = h && h.status === "ok";
            status.firstChild.className = "dot " + (ok ? "ok" : "bad");
            status.lastChild.textContent = ok ? "Monitoring active" : "API reporting a problem";
        }).catch(() => {
            status.firstChild.className = "dot bad";
            status.lastChild.textContent = "API unreachable";
        });

        // Sequential on purpose: the first call fills the API cache and the API throttles bursts
        let summary = null;
        try {
            const t = await data.trend();
            if (myRun !== run) return;
            summary = data.summarize(t.days, days);
            renderKpis(summary, days);
            sub.textContent = "CloudTrail detections · " + shortDate(new Date(summary.rows[0].day + "T00:00:00Z")) + " – " + shortDate(new Date(summary.rows[summary.rows.length - 1].day + "T00:00:00Z"));
            if (summary.now.total === 0) trendCard.empty("No incidents in this range");
            else trendCard.show(el("div", {}, [legend(), stackedArea(summary.rows, "Incidents per day by severity, last " + days + " days")]));
            trendCard.note(t.generatedAt ? "Computed " + new Date(t.generatedAt * 1000).toISOString().slice(11, 16) + " UTC. Recomputed when a new incident arrives." : "");
        } catch (err) {
            if (myRun !== run) return;
            kpiRow.replaceChildren(el("div", { class: "card panel span-all" }, [el("div", { class: "error-box" }, [
                el("p", { text: "Could not load the totals. " + err.message }),
                el("button", { class: "btn", type: "button", text: "Retry", onclick: refresh })
            ])]));
            trendCard.error(err, refresh);
        }

        mitreCard.load(() => data.mitre(days), (res) => {
            const rows = res.data.slice(0, 6).map((r) => ({ label: r.technique, sub: techName(r.technique), value: Number(r.incidents) }));
            const total = summary ? summary.now.total : rows.reduce((n, r) => n + r.value, 0);
            mitreCard.show(rows.length ? donut(rows, total, "incidents", "Top MITRE techniques") : el("div", { class: "empty", text: "No data in this range" }));
        });

        try {
            const res = await data.latest(8);
            if (myRun !== run) return;
            if (!res.items.length) table.empty("No incidents yet");
            else table.setRows(res.items, false);
            latestFoot.textContent = res.items.length ? "Showing the latest " + res.items.length + " incidents" : "";
        } catch (err) {
            if (myRun !== run) return;
            table.error(err, refresh);
        }
    }

    refresh();
    return { refresh, destroy() { run++; } };
}
