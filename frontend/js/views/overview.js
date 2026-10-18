// Overview: the few things worth seeing first. KPIs, the trend, top techniques, latest incidents.

import * as data from "../data.js";
import { el, SEVERITIES, sevClass, shortDate, techName, countUp } from "../dom.js";
import { stackedArea, donut, legend } from "../charts.js";
import { panel, pageHead, incidentTable } from "./ui.js";

function delta(now, before, days) {
    if (days === 0) return el("p", { class: "delta", text: "Since the first detection" });
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

    // Values already shown: a new incident makes the figure count up from the old one instead of jumping
    const shownKpi = new Map();

    function renderKpis(summary, days, soft) {
        const cards = [["Total incidents", "total", null], ...SEVERITIES.map((s) => [s.charAt(0) + s.slice(1).toLowerCase(), s, s])];
        kpiRow.classList.toggle("soft", soft);
        kpiRow.replaceChildren(...cards.map(([label, key, sev], i) => {
            const value = el("div", { class: "value" });
            countUp(value, summary.now[key], { from: soft ? (shownKpi.get(key) || 0) : 0 });
            shownKpi.set(key, summary.now[key]);
            return el("div", { class: "card kpi", vars: Object.assign({ "--i": String(i) }, sev ? { "--c": "var(--sev-" + sevClass(sev) + ")" } : {}) }, [
                el("div", { class: "label" }, [sev ? el("i", { class: "sev-dot", vars: { "--c": "var(--sev-" + sevClass(sev) + ")" } }) : null, label]),
                value,
                delta(summary.now[key], summary.before ? summary.before[key] : null, days)
            ]);
        }));
    }

    let run = 0;
    // soft: called by the automatic refresh when a new incident arrives. Nothing goes back to a skeleton,
    // the figures count up and new rows are highlighted
    async function refresh(soft = false) {
        const myRun = ++run;
        const days = ctx.days();
        if (!soft) {
            shownKpi.clear();
            kpiSkeleton();
            trendCard.loading();
            mitreCard.loading();
            table.resetSeen();
            table.loading(6);
        }

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
            if (days === 0) {
                // The totals of all time are exact: /stats counts every incident, while the daily chart only reaches back 90 days
                const all = (await data.stats()).windows.all || {};
                if (myRun !== run) return;
                summary.now = { total: Number(all.total || 0) };
                SEVERITIES.forEach((s) => { summary.now[s] = Number(all[s] || 0); });
                summary.before = null;
            }
            renderKpis(summary, days, soft);
            sub.textContent = "CloudTrail detections · " + (days === 0 ? "all time" : shortDate(new Date(summary.rows[0].day + "T00:00:00Z")) + " – " + shortDate(new Date(summary.rows[summary.rows.length - 1].day + "T00:00:00Z")));
            if (summary.now.total === 0) trendCard.empty("No incidents in this range");
            else trendCard.show(el("div", {}, [legend(), stackedArea(summary.rows, "Incidents per day by severity, last " + summary.rows.length + " days")]));
            trendCard.note((t.generatedAt ? "Computed " + new Date(t.generatedAt * 1000).toISOString().slice(11, 16) + " UTC. Recomputed when a new incident arrives." : "")
                + (days === 0 ? " The totals above are for all time; this chart shows the last " + data.API_MAX_DAYS + " days, the most the API reports." : ""));
        } catch (err) {
            if (myRun !== run) return;
            if (!soft) {
                kpiRow.replaceChildren(el("div", { class: "card panel span-all" }, [el("div", { class: "error-box" }, [
                    el("p", { text: "Could not load the totals. " + err.message }),
                    el("button", { class: "btn", type: "button", text: "Retry", onclick: () => refresh() })
                ])]));
                trendCard.error(err, () => refresh());
            }
        }

        mitreCard.load(() => data.mitre(days), (res) => {
            const rows = res.data.slice(0, 6).map((r) => ({ label: r.technique, sub: techName(r.technique), value: Number(r.incidents) }));
            const total = summary ? summary.now.total : rows.reduce((n, r) => n + r.value, 0);
            mitreCard.show(rows.length ? donut(rows, total, "incidents", "Top MITRE techniques") : el("div", { class: "empty", text: "No data in this range" }));
        }, { soft });

        try {
            const res = await data.latest(8);
            if (myRun !== run) return;
            if (!res.items.length) table.empty("No incidents yet");
            else table.setRows(res.items, false, soft);
            latestFoot.textContent = res.items.length ? "Showing the latest " + res.items.length + " incidents" : "";
        } catch (err) {
            if (myRun !== run) return;
            if (!soft) table.error(err, () => refresh());
        }
    }

    refresh();
    return { refresh, destroy() { run++; } };
}
