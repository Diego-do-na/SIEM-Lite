// Analytics: the four fixed Athena reports. Each card loads and fails on its own.

import * as data from "../data.js";
import { el, techName, fmtNum } from "../dom.js";
import { stackedArea, donut, rankedBars, histogram, legend } from "../charts.js";
import { panel, pageHead } from "./ui.js";

function computedNote(res) {
    if (!res || !res.generatedAt) return "";
    return "Computed " + new Date(res.generatedAt * 1000).toISOString().slice(11, 16) + " UTC" + (res.cached ? " (cached)" : "") + ". Recomputed when a new incident arrives.";
}

export function mount(root, ctx) {
    const trendCard = panel({ title: "Incidents over time", sub: "Daily detections by severity · UTC", minHeight: 250 });
    const mitreCard = panel({ title: "Top MITRE ATT&CK techniques", sub: "Incidents per technique", minHeight: 250 });
    const ipsCard = panel({ title: "Top source IPs", sub: "Most active addresses · highest score seen", minHeight: 220 });
    const scoreCard = panel({ title: "Score distribution", sub: "Incident count by risk score, in steps of 100", minHeight: 220 });
    root.append(
        pageHead("Analytics", "Reports computed in Athena, refreshed when a new incident arrives"),
        el("div", { class: "grid-2" }, [trendCard.root, mitreCard.root]),
        el("div", { class: "grid-2" }, [ipsCard.root, scoreCard.root])
    );

    let run = 0;
    async function refresh() {
        const myRun = ++run;
        const days = ctx.days();
        const stale = () => myRun !== run;

        // Sequential on purpose: the first call fills the API cache and the API throttles bursts
        await trendCard.load(() => data.trend(), (t) => {
            const summary = data.summarize(t.days, days);
            if (summary.now.total === 0) trendCard.empty("No incidents in this range");
            else trendCard.show(el("div", {}, [legend(), stackedArea(summary.rows, "Incidents per day by severity, last " + days + " days")]));
            trendCard.note(computedNote(t));
        });
        if (stale()) return;
        await mitreCard.load(() => data.mitre(days), (res) => {
            const rows = res.data.slice(0, 8).map((r) => ({ label: r.technique, sub: techName(r.technique), value: Number(r.incidents) }));
            const total = rows.reduce((n, r) => n + r.value, 0);
            mitreCard.show(rows.length ? donut(rows, total, "technique hits", "Top MITRE techniques") : el("div", { class: "empty", text: "No data in this range" }));
            mitreCard.note(computedNote(res));
        });
        if (stale()) return;
        await ipsCard.load(() => data.topIps(days), (res) => {
            const rows = res.data.map((r) => ({ label: r.ip, who: "max score " + fmtNum(r.maxScore), value: Number(r.incidents) }));
            ipsCard.show(rankedBars(rows));
            ipsCard.note(computedNote(res));
        });
        if (stale()) return;
        await scoreCard.load(() => data.scores(days), (res) => {
            const rows = res.data.map((r) => {
                const low = parseInt(String(r.bucket).split("-")[0], 10);
                return { low, high: low + 99, value: Number(r.incidents) };
            }).sort((a, b) => a.low - b.low);
            scoreCard.show(histogram(rows, "Score distribution"));
            scoreCard.note("Higher scores mean greater potential risk. Thresholds: Low from 1, Medium 200, High 400, Critical 600. " + computedNote(res));
        });
    }

    refresh();
    return { refresh, destroy() { run++; } };
}
