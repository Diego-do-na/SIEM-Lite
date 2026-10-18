// Analytics. The four Athena reports (trend, MITRE, top IPs, score distribution) come from the API.
// Everything else (activity by hour, tactics, users, mitigation, duration, technique by severity)
// is computed here from the most recent incidents of the range, so it needs no new endpoint.
// Each card loads and fails on its own.

import * as data from "../data.js";
import * as stats from "../stats.js";
import { el, techName, fmtNum, fmtPct, fmtDuration, sevClass } from "../dom.js";
import { stackedArea, donut, rankedBars, ratioBars, histogram, heatmap, severityMatrix, legend } from "../charts.js";
import { panel, pageHead, statCard } from "./ui.js";
import { attackMatrix } from "./matrix.js";
import { regionMap } from "./regionmap.js";
import * as ex from "../explain.js";
import { REGION_POINTS } from "../worldmap.js";

// "Total" asks the reports for the most days the API gives, so cards that come from it say so
let allTime = false;

function computedNote(res) {
    if (!res || !res.generatedAt) return "";
    return (allTime ? "All time shows the last " + data.API_MAX_DAYS + " days here, the most the API reports. " : "") + "Computed " + new Date(res.generatedAt * 1000).toISOString().slice(11, 16) + " UTC" + (res.cached ? " (cached)" : "") + ". Recomputed when a new incident arrives.";
}

function sampleNote(res) {
    return res.truncated
        ? "Based on the latest " + fmtNum(res.items.length) + " incidents of this range; there are more, so figures are an estimate."
        : "Based on all " + fmtNum(res.items.length) + " incidents of this range.";
}

const sevLabel = (s) => s.charAt(0) + s.slice(1).toLowerCase();
const hourRange = (h) => String(h).padStart(2, "0") + ":00–" + String((h + 1) % 24).padStart(2, "0") + ":00";

export function mount(root, ctx) {
    const strip = el("section", { class: "grid-stats", "aria-label": "Key figures" });
    const trendCard = panel({ title: "Incidents over time", sub: "Daily detections by severity · UTC", minHeight: 250 });
    const mitreCard = panel({ title: "Top MITRE ATT&CK techniques", sub: "Incidents per technique", minHeight: 250 });
    const attackCard = panel({ title: "MITRE ATT&CK coverage", sub: "What the detection rules cover, by tactic · select a technique to read about it", minHeight: 200 });
    const mapCard = panel({ title: "Activity by region", sub: "Where in AWS the activity happened · incidents per region", minHeight: 260, action: el("span", { class: "pill", title: "Region per incident is part of the 1.1 API. Until then it shows in demo data only.", text: "Preview" }) });
    const heatCard = panel({ title: "When incidents happen", sub: "Weekday and hour of day · UTC", minHeight: 200 });
    const tacticCard = panel({ title: "MITRE tactics", sub: "What the attacker was trying to achieve", minHeight: 220 });
    const mitigationCard = panel({ title: "Automated response", sub: "Share of incidents mitigated, by severity", minHeight: 220 });
    const ipsCard = panel({ title: "Top source IPs", sub: "Most active addresses · highest score seen", minHeight: 220 });
    const usersCard = panel({ title: "Top IAM users", sub: "Identities behind the most incidents", minHeight: 220 });
    const scoreCard = panel({ title: "Score distribution", sub: "Incident count by risk score, in steps of 100", minHeight: 220 });
    const durationCard = panel({ title: "Incident duration", sub: "Average time from first to last event · median beside each bar", minHeight: 220 });
    const matrixCard = panel({ title: "Techniques by severity", sub: "Which techniques reach the high severities", minHeight: 200 });

    root.append(
        pageHead("Analytics", "Reports computed in Athena plus statistics from the incidents themselves"),
        strip,
        el("div", { class: "grid-2" }, [trendCard.root, mitreCard.root]),
        el("div", { class: "grid-1" }, [attackCard.root]),
        el("div", { class: "grid-1" }, [mapCard.root]),
        el("div", { class: "grid-1" }, [heatCard.root]),
        el("div", { class: "grid-2" }, [tacticCard.root, mitigationCard.root]),
        el("div", { class: "grid-2" }, [ipsCard.root, usersCard.root]),
        el("div", { class: "grid-2" }, [scoreCard.root, durationCard.root]),
        el("div", { class: "grid-1" }, [matrixCard.root])
    );

    function stripSkeleton() {
        strip.replaceChildren(...Array.from({ length: 6 }, () => el("div", { class: "card kpi" }, [el("div", { class: "skel", vars: { "--h": "74px" } })])));
    }

    function renderStrip(res) {
        const s = stats.summary(res.items);
        if (!s.total) {
            strip.replaceChildren(el("div", { class: "card panel span-all" }, [el("div", { class: "empty", text: "No incidents in this range" })]));
            return;
        }
        strip.replaceChildren(
            statCard("Mitigation rate", fmtPct(s.mitigationRate), s.mitigated + " of " + s.total + " handled automatically"),
            statCard("Average duration", fmtDuration(s.avgDuration), "Median " + fmtDuration(s.medianDuration)),
            statCard("Median risk score", fmtNum(s.medianScore), "90th percentile " + fmtNum(s.p90Score) + " · max " + fmtNum(s.maxScore)),
            statCard("Source IPs", fmtNum(s.ips), s.repeatIps + " seen in more than one incident"),
            statCard("IAM users", fmtNum(s.users), s.topUser ? "Most active: " + s.topUser : ""),
            statCard("Peak hour (UTC)", hourRange(s.peakHour), "Busiest day: " + s.peakDay)
        );
    }

    let run = 0;
    async function refresh(soft = false) {
        const myRun = ++run;
        const days = ctx.days();
        allTime = days === 0;
        const stale = () => myRun !== run;
        const opts = { soft };
        if (!soft) stripSkeleton();

        // Sequential on purpose: the first call fills the API cache and the API throttles bursts
        await trendCard.load(() => data.trend(), (t) => {
            const summary = data.summarize(t.days, days);
            if (summary.now.total === 0) trendCard.empty("No incidents in this range");
            else {
                trendCard.show(el("div", {}, [legend(), stackedArea(summary.rows, "Incidents per day by severity, last " + summary.rows.length + " days")]));
                trendCard.explain(ex.trendExplain(summary.rows));
            }
            trendCard.note(computedNote(t));
        }, opts);
        if (stale()) return;
        await mitreCard.load(() => data.mitre(days), (res) => {
            const rows = res.data.slice(0, 8).map((r) => ({ label: r.technique, sub: techName(r.technique), value: Number(r.incidents) }));
            const total = rows.reduce((n, r) => n + r.value, 0);
            mitreCard.show(rows.length ? donut(rows, total, "technique hits", "Top MITRE techniques") : el("div", { class: "empty", text: "No data in this range" }));
            mitreCard.explain(ex.techniqueExplain(rows));
            mitreCard.note(computedNote(res));
        }, opts);
        if (stale()) return;
        await attackCard.load(() => data.mitre(days), (res) => {
            const counts = {};
            res.data.forEach((r) => { counts[r.technique] = Number(r.incidents); });
            attackCard.show(attackMatrix(counts));
            attackCard.explain(ex.coverageExplain(counts));
            attackCard.note(allTime ? "All time shows the last " + data.API_MAX_DAYS + " days here, the most the API reports." : "");
        }, opts);
        if (stale()) return;
        await ipsCard.load(() => data.topIps(days), (res) => {
            const rows = res.data.map((r) => ({ label: r.ip, who: "max score " + fmtNum(r.maxScore), value: Number(r.incidents) }));
            ipsCard.show(rankedBars(rows));
            ipsCard.explain(ex.ipsExplain(res.data.map((r) => ({ ip: r.ip, incidents: Number(r.incidents), maxScore: Number(r.maxScore) }))));
            ipsCard.note(computedNote(res));
        }, opts);
        if (stale()) return;
        await scoreCard.load(() => data.scores(days), (res) => {
            const rows = res.data.map((r) => {
                const low = parseInt(String(r.bucket).split("-")[0], 10);
                return { low, high: low + 99, value: Number(r.incidents) };
            }).sort((a, b) => a.low - b.low);
            scoreCard.show(histogram(rows, "Score distribution"));
            scoreCard.explain(ex.scoreExplain(rows));
            scoreCard.note("Higher scores mean greater potential risk. Thresholds: Low from 1, Medium 200, High 400, Critical 600. " + computedNote(res));
        }, opts);
        if (stale()) return;

        // The rest comes from one shared sample of incidents
        const sampled = () => data.sample(days);
        const empty = (card) => card.empty("No incidents in this range");
        const from = (card, build) => card.load(sampled, (res) => {
            if (!res.items.length) { empty(card); return; }
            build(res);
            card.note(sampleNote(res));
        }, opts);

        data.sample(days).then((res) => { if (!stale()) renderStrip(res); }).catch((err) => {
            if (stale() || soft) return;
            strip.replaceChildren(el("div", { class: "card panel span-all" }, [el("div", { class: "error-box" }, [
                el("p", { text: "Could not load the key figures. " + err.message }),
                el("button", { class: "btn", type: "button", text: "Retry", onclick: () => refresh() })
            ])]));
        });

        await Promise.all([
            from(mapCard, (res) => {
                mapCard.show(regionMap(res.items));
                mapCard.explain(ex.regionExplain(res.items, (r) => (REGION_POINTS[r] ? REGION_POINTS[r][2] : r)));
            }),
            from(heatCard, (res) => {
                const a = stats.activity(res.items);
                heatCard.show(heatmap(a.rows, a.max, "incident"));
                heatCard.explain(ex.heatExplain(a));
            }),
            from(tacticCard, (res) => {
                const rows = stats.byTactic(res.items).map((r) => ({ label: r.label, value: r.value, mono: false }));
                tacticCard.show(rankedBars(rows));
                tacticCard.explain(ex.tacticExplain(rows, res.items.length));
            }),
            from(mitigationCard, (res) => {
                const by = stats.mitigationBySeverity(res.items);
                mitigationCard.show(ratioBars(by.map((r) => ({
                    label: sevLabel(r.sev), color: "var(--sev-" + sevClass(r.sev) + ")", part: r.mitigated, whole: r.total
                }))));
                mitigationCard.explain(ex.mitigationExplain(by));
            }),
            from(usersCard, (res) => {
                const rows = stats.topUsers(res.items).map((r) => ({
                    label: r.user, who: "max score " + fmtNum(r.maxScore) + " · " + r.ips + (r.ips === 1 ? " IP" : " IPs"), value: r.count
                }));
                usersCard.show(rankedBars(rows));
                usersCard.explain(ex.usersExplain(stats.topUsers(res.items), res.items.length));
            }),
            from(durationCard, (res) => {
                const all = stats.durationBySeverity(res.items);
                durationCard.explain(ex.durationExplain(all));
                const rows = all.filter((r) => r.count).map((r) => ({
                    label: sevLabel(r.sev), mono: false, who: "median " + fmtDuration(r.median), value: r.avg, display: fmtDuration(r.avg),
                    color: "var(--sev-" + sevClass(r.sev) + ")"
                }));
                durationCard.show(rankedBars(rows));
            }),
            from(matrixCard, (res) => {
                const grid = stats.techniqueSeverity(res.items);
                matrixCard.show(severityMatrix(grid, techName));
                matrixCard.explain(ex.severityMatrixExplain(grid));
            })
        ]);
    }

    refresh();
    return { refresh, destroy() { run++; } };
}
