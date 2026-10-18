// What a card says about itself once it is expanded: how to read the chart, what stands out in it, and the exact figures.
//
// The "what stands out" sentences are plain rules over the numbers on screen (a maximum, a share, a comparison of two halves).
// There is no model behind them, so every sentence can be checked against the table beside it.
// Each builder returns { read: [text], findings: [text], table: { head, rows, num, note } }; cells may be text or DOM nodes.

import { el, SEVERITIES, sevOfScore, shortDate, fmtNum, fmtPct, fmtDuration, plural, techName } from "./dom.js";
import { TACTICS, TECHNIQUES, tacticOf } from "./mitre.js";
import { techChip } from "./techchip.js";
import { entityLink } from "./links.js";

const sum = (list) => list.reduce((n, x) => n + x, 0);
const pct = (n, total) => (total ? Math.round((n / total) * 100) + "%" : "–");
const sevName = (s) => s.charAt(0) + s.slice(1).toLowerCase();
const dayLabel = (day) => shortDate(new Date(day + "T00:00:00Z"));
const hh = (h) => String(h).padStart(2, "0") + ":00";

// ---------- Drawing ----------

export function explainView(spec) {
    if (!spec) return [];
    const left = [];
    if (spec.read && spec.read.length) {
        left.push(el("section", { class: "ex-block" }, [el("h3", { text: "How to read this" }), ...spec.read.map((p) => el("p", { text: p }))]));
    }
    if (spec.findings && spec.findings.length) {
        left.push(el("section", { class: "ex-block" }, [el("h3", { text: "What stands out" }), el("ul", { class: "ex-list" }, spec.findings.map((f) => el("li", { text: f })))]));
    }
    const parts = [];
    if (left.length) parts.push(el("div", { class: "ex-left" }, left));
    if (spec.table && spec.table.rows.length) {
        const t = spec.table;
        const num = new Set(t.num || []);
        parts.push(el("section", { class: "ex-block ex-data" }, [
            el("h3", { text: "The numbers" }),
            el("div", { class: "ex-table-wrap", tabindex: "0", role: "region", "aria-label": "Data table" }, [
                el("table", { class: "ex-table" }, [
                    el("thead", {}, [el("tr", {}, t.head.map((h, i) => el("th", { scope: "col", class: num.has(i) ? "num" : "", text: h })))]),
                    el("tbody", {}, t.rows.map((row) => el("tr", {}, row.map((cell, i) => el("td", { class: num.has(i) ? "num" : "" }, [cell])))))
                ])
            ]),
            t.note ? el("p", { class: "ex-note", text: t.note }) : null
        ]));
    }
    return parts;
}

// ---------- Incidents over time ----------
// rows: one per UTC day { day, CRITICAL, HIGH, MEDIUM, LOW, total }

export function trendExplain(rows) {
    const total = sum(rows.map((r) => r.total));
    const findings = [];
    if (total) {
        const busiest = rows.reduce((a, b) => (b.total > a.total ? b : a), rows[0]);
        const quiet = rows.filter((r) => !r.total).length;
        const serious = sum(rows.map((r) => r.CRITICAL + r.HIGH));
        const lastCritical = rows.slice().reverse().find((r) => r.CRITICAL);
        findings.push(fmtNum(total) + " incidents in " + plural(rows.length, "day") + ", " + (total / rows.length).toFixed(1) + " a day on average.");
        findings.push("Busiest day: " + dayLabel(busiest.day) + " with " + plural(busiest.total, "incident") + (busiest.CRITICAL ? ", " + busiest.CRITICAL + " of them Critical" : "") + ".");
        findings.push(pct(serious, total) + " of the incidents (" + fmtNum(serious) + ") are Critical or High." + (lastCritical ? " The latest Critical was on " + dayLabel(lastCritical.day) + "." : " There were no Critical incidents."));
        findings.push(quiet ? plural(quiet, "day") + " had no incidents at all." : "Every day in the range had at least one incident.");
        if (rows.length >= 6) {
            const half = Math.floor(rows.length / 2);
            const first = sum(rows.slice(0, half).map((r) => r.total));
            const second = sum(rows.slice(half).map((r) => r.total));
            if (first > 0) {
                const change = ((second - first) / first) * 100;
                findings.push(Math.abs(change) < 5
                    ? "Activity is steady: the second half of the range has about the same incidents as the first."
                    : "The second half of the range has " + Math.abs(Math.round(change)) + "% " + (change > 0 ? "more" : "fewer") + " incidents than the first half.");
            }
        }
    }
    return {
        read: [
            "Each day is a stack of the four severities. The height of the whole stack is the number of incidents that day; Low sits at the bottom and Critical on top.",
            "A taller top band means more serious activity, not only more activity. Days are UTC, and moving over the chart shows the figures of a day."
        ],
        findings,
        table: {
            head: ["Day (UTC)", "Critical", "High", "Medium", "Low", "Total"], num: [1, 2, 3, 4, 5],
            rows: rows.slice().reverse().map((r) => [dayLabel(r.day), ...SEVERITIES.map((s) => fmtNum(r[s])), fmtNum(r.total)]),
            note: "Newest day first."
        }
    };
}

// ---------- Techniques ----------
// rows: [{ label: "T1485", value }]

export function techniqueExplain(rows) {
    const hits = sum(rows.map((r) => r.value));
    const findings = [];
    if (rows.length) {
        const top = rows[0];
        findings.push(top.label + " " + (techName(top.label) ? "(" + techName(top.label) + ") " : "") + "leads with " + plural(top.value, "incident") + ", " + pct(top.value, hits) + " of the technique hits shown.");
        if (rows.length > 1) findings.push("The top two techniques together are " + pct(rows[0].value + rows[1].value, hits) + " of the hits; " + plural(rows.length, "technique") + " appear in total.");
        if (TECHNIQUES[top.label]) findings.push("What the leader means here: " + TECHNIQUES[top.label].summary);
        if (rows.some((r) => r.label === "T1110")) findings.push("T1110 also labels denied API calls that have no more specific rule, so a high count there usually means many denied calls, not necessarily password guessing.");
    }
    return {
        read: [
            "Each slice is a MITRE ATT&CK technique, a known way an attacker reaches a goal. Its size is the number of incidents that carry it.",
            "One incident can carry more than one technique, so the slices can add up to more than the number of incidents. Select a technique id in the table to read what it is and what to check."
        ],
        findings,
        table: {
            head: ["Technique", "Name", "Tactic", "Incidents", "Share"], num: [3, 4],
            rows: rows.map((r) => [techChip(r.label), techName(r.label) || "", tacticOf(r.label), fmtNum(r.value), pct(r.value, hits)])
        }
    };
}

// ---------- ATT&CK coverage ----------
// counts: { T1485: 12, ... }

export function coverageExplain(counts) {
    const covered = Object.values(TECHNIQUES);
    const lit = new Set(covered.map((t) => t.tactic));
    const fired = covered.filter((t) => counts[t.id] > 0);
    const silent = covered.filter((t) => !(counts[t.id] > 0));
    const gaps = TACTICS.filter((t) => !lit.has(t.name)).map((t) => t.name);
    const findings = [
        plural(covered.length, "technique") + " have a detection rule, across " + lit.size + " of " + TACTICS.length + " tactics.",
        fired.length ? plural(fired.length, "technique") + " fired in this range: " + fired.map((t) => t.id).join(", ") + "." : "No covered technique fired in this range."
    ];
    if (fired.length && silent.length) findings.push("Covered but quiet in this range: " + silent.map((t) => t.id).join(", ") + ". Quiet is good news, but a rule that never fires is worth testing now and then.");
    if (gaps.length) findings.push("Not covered yet: " + gaps.join(", ") + ". These are the gaps, shown on purpose.");
    return {
        read: [
            "Each column is a tactic of the ATT&CK matrix for cloud environments: the goal the attacker has at that stage. The techniques inside it are the ways of reaching that goal.",
            "A lit technique has a SIEM Lite rule, and the number is the incidents it raised in this range. A column that says \"No rule yet\" is something the detection does not look for today."
        ],
        findings,
        table: {
            head: ["Tactic", "Technique", "Name", "Incidents"], num: [3],
            rows: covered.map((t) => [t.tactic, techChip(t.id), t.name, fmtNum(counts[t.id] || 0)])
        }
    };
}

// ---------- Regions ----------

export function regionExplain(items, nameOf = (r) => r) {
    const counts = new Map();
    items.forEach((i) => { if (i.awsRegion) counts.set(i.awsRegion, (counts.get(i.awsRegion) || 0) + 1); });
    const read = [
        "Each dot sits on an AWS region and grows with the number of incidents whose API call was made there. CloudTrail records the region of every call.",
        "Activity in a region you do not normally use is a classic sign of someone exploring with stolen credentials, so a new dot far from the usual one deserves a look."
    ];
    if (!counts.size) return { read: read.concat("The incident list does not include the region yet; it arrives with the 1.1 API. The demo data already has it."), findings: [] };
    const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const total = sum(ranked.map(([, n]) => n));
    const findings = [
        ranked[0][0] + " (" + nameOf(ranked[0][0]) + ") has the most: " + plural(ranked[0][1], "incident") + ", " + pct(ranked[0][1], total) + " of those with a region.",
        ranked.length > 1 ? plural(ranked.length, "region") + " saw activity; " + pct(total - ranked[0][1], total) + " of the incidents came from outside the top one." : "All the activity came from one region."
    ];
    return {
        read, findings,
        table: { head: ["Region", "Place", "Incidents", "Share"], num: [2, 3], rows: ranked.map(([region, n]) => [region, nameOf(region), fmtNum(n), pct(n, total)]) }
    };
}

// ---------- When incidents happen ----------
// act: stats.activity(items) { rows: [{label, cells[24]}], hours[24], days[7 Sun..Sat] }

export function heatExplain(act) {
    const total = sum(act.hours);
    const findings = [];
    if (total) {
        let best = { n: -1 };
        act.rows.forEach((row) => row.cells.forEach((n, h) => { if (n > best.n) best = { n, day: row.label, h }; }));
        const hourTop = act.hours.indexOf(Math.max(...act.hours));
        const weekend = act.rows.filter((r) => r.label === "Sat" || r.label === "Sun").reduce((n, r) => n + sum(r.cells), 0);
        const busiest = act.rows.reduce((a, b) => (sum(b.cells) > sum(a.cells) ? b : a));
        const quietHours = act.hours.filter((n) => n === 0).length;
        findings.push("The single busiest hour is " + best.day + " " + hh(best.h) + " UTC, with " + plural(best.n, "incident") + ".");
        findings.push("Across the week, " + hh(hourTop) + "–" + hh((hourTop + 1) % 24) + " UTC is the busiest hour of the day (" + pct(act.hours[hourTop], total) + " of incidents) and " + busiest.label + " the busiest weekday.");
        findings.push(pct(weekend, total) + " of the incidents happened on a weekend; an even spread would be about 29%." + (weekend / total > 0.4 ? " Weekend activity is high, which is worth a look if nobody works then." : ""));
        if (quietHours) findings.push(plural(quietHours, "hour") + " of the day never had an incident in this range.");
    }
    const blocks = [0, 4, 8, 12, 16, 20];
    return {
        read: [
            "Rows are weekdays and columns are hours of the day. The darker a cell, the more incidents started in that hour.",
            "Times are UTC, not local time: convert before comparing with the working hours of the team. Activity at hours when nobody should be working is the interesting part."
        ],
        findings,
        table: {
            head: ["Day", ...blocks.map((h) => hh(h).slice(0, 2) + "–" + hh(h + 4).slice(0, 2)), "Total"], num: [1, 2, 3, 4, 5, 6, 7],
            rows: act.rows.map((row) => [row.label, ...blocks.map((h) => fmtNum(sum(row.cells.slice(h, h + 4)))), fmtNum(sum(row.cells))]),
            note: "Incidents per block of four hours, UTC."
        }
    };
}

// ---------- Tactics ----------
// rows: [{ label, value }], total: incidents in the sample

export function tacticExplain(rows, total) {
    const findings = [];
    if (rows.length) {
        findings.push(rows[0].label + " is the most common goal: " + plural(rows[0].value, "incident") + ", " + pct(rows[0].value, total) + " of all incidents.");
        findings.push(plural(rows.length, "tactic") + " appear in this range." + (rows.length === 1 ? " Every incident has the same goal." : ""));
        const impact = rows.find((r) => r.label === "Impact");
        if (impact) findings.push("Impact means data or services were made unavailable. " + pct(impact.value, total) + " of the incidents reach it.");
    }
    return {
        read: [
            "A tactic is the goal the attacker has at one stage: hiding what they do (Defense Evasion), getting at passwords (Credential Access), causing damage (Impact).",
            "Each bar counts the incidents with at least one technique of that tactic. An incident that touches two tactics is counted in both, so the bars can add up to more than the incidents."
        ],
        findings,
        table: { head: ["Tactic", "Incidents", "Share of incidents"], num: [1, 2], rows: rows.map((r) => [r.label, fmtNum(r.value), pct(r.value, total)]) }
    };
}

// ---------- Automated response ----------
// rows: stats.mitigationBySeverity -> [{ sev, total, mitigated }]

export function mitigationExplain(rows) {
    const total = sum(rows.map((r) => r.total));
    const done = sum(rows.map((r) => r.mitigated));
    const findings = [];
    if (total) {
        findings.push(fmtNum(done) + " of " + fmtNum(total) + " incidents (" + pct(done, total) + ") were mitigated by the automated response.");
        const worst = rows.filter((r) => r.total).sort((a, b) => a.mitigated / a.total - b.mitigated / b.total)[0];
        const best = rows.filter((r) => r.total).sort((a, b) => b.mitigated / b.total - a.mitigated / a.total)[0];
        if (worst && best && worst.sev !== best.sev) findings.push(sevName(best.sev) + " has the highest rate (" + pct(best.mitigated, best.total) + ") and " + sevName(worst.sev) + " the lowest (" + pct(worst.mitigated, worst.total) + ").");
        const critical = rows.find((r) => r.sev === "CRITICAL");
        if (critical && critical.total - critical.mitigated > 0) findings.push(plural(critical.total - critical.mitigated, "Critical incident") + (critical.total - critical.mitigated === 1 ? " was" : " were") + " not mitigated automatically. Those need a person: open them from Incidents.");
    }
    return {
        read: [
            "Mitigated means the automated response ran a corrective action: it restarted logging, recreated a trail, re-enabled a key or cancelled its deletion. Each bar is the share of incidents of that severity where that happened.",
            "A rate below 100% is not a failure. Security group changes, trail updates and generic denied calls are alert-only today: SIEM Lite raises the incident and leaves the decision to a person."
        ],
        findings,
        table: {
            head: ["Severity", "Incidents", "Mitigated", "Not mitigated", "Rate"], num: [1, 2, 3, 4],
            rows: rows.map((r) => [sevName(r.sev), fmtNum(r.total), fmtNum(r.mitigated), fmtNum(r.total - r.mitigated), r.total ? pct(r.mitigated, r.total) : "–"])
        }
    };
}

// ---------- Top source IPs ----------
// rows: [{ ip, incidents, maxScore }]

export function ipsExplain(rows) {
    const total = sum(rows.map((r) => r.incidents));
    const findings = [];
    if (rows.length) {
        const top = rows[0];
        const repeat = rows.filter((r) => r.incidents > 1).length;
        const hottest = rows.slice().sort((a, b) => b.maxScore - a.maxScore)[0];
        findings.push(top.ip + " is the most active: " + plural(top.incidents, "incident") + ", " + pct(top.incidents, total) + " of those listed.");
        findings.push(repeat ? repeat + (repeat === 1 ? " address appears" : " addresses appear") + " in more than one incident; the same source coming back is worth more attention than a one-off." : "Each address appears in a single incident.");
        findings.push("The highest score belongs to " + hottest.ip + ": " + fmtNum(hottest.maxScore) + ", which is " + sevName(sevOfScore(hottest.maxScore)) + ".");
    }
    return {
        read: [
            "The source IP is the address the API call came from, as recorded by CloudTrail. The bar is how many incidents it took part in; the note beside it is the highest score it reached.",
            "An address is not always a person: it can be a VPN, an office network shared by many people, or an AWS service acting for you. Select an address to see everything it did."
        ],
        findings,
        table: {
            head: ["Source IP", "Incidents", "Highest score", "Severity of that score"], num: [1, 2],
            rows: rows.map((r) => [entityLink("ip", r.ip), fmtNum(r.incidents), fmtNum(r.maxScore), sevName(sevOfScore(r.maxScore))])
        }
    };
}

// ---------- Top IAM users ----------
// rows: stats.topUsers -> [{ user, count, maxScore, ips }]

export function usersExplain(rows, total) {
    const findings = [];
    if (rows.length) {
        const top = rows[0];
        const many = rows.filter((r) => r.ips > 1);
        findings.push(top.user + " is behind the most incidents: " + plural(top.count, "incident") + ", " + pct(top.count, total) + " of the range.");
        if (many.length) findings.push(many.map((r) => r.user).slice(0, 3).join(", ") + (many.length > 3 ? " and others" : "") + " acted from more than one address. That can be normal for a person who travels or a pipeline, but it can also mean a key is used where it should not be.");
        const hottest = rows.slice().sort((a, b) => b.maxScore - a.maxScore)[0];
        findings.push("The highest score is " + fmtNum(hottest.maxScore) + " (" + sevName(sevOfScore(hottest.maxScore)) + "), reached by " + hottest.user + ".");
    }
    return {
        read: [
            "These are the IAM identities whose credentials made the calls behind the incidents. The bar is the number of incidents; the note is the highest score and how many addresses the identity used.",
            "Service accounts that appear often usually point at a script or a pipeline that needs fixing, while a person's name at the top asks for a conversation. Select a name to see its history."
        ],
        findings,
        table: {
            head: ["IAM user", "Incidents", "Highest score", "Addresses"], num: [1, 2, 3],
            rows: rows.map((r) => [entityLink("user", r.user, { mono: false }), fmtNum(r.count), fmtNum(r.maxScore), fmtNum(r.ips)])
        }
    };
}

// ---------- Score distribution ----------
// rows: [{ low, high, value }]

export function scoreExplain(rows) {
    const total = sum(rows.map((r) => r.value));
    const findings = [];
    if (total) {
        const top = rows.reduce((a, b) => (b.value > a.value ? b : a));
        const band = (name) => sum(rows.filter((r) => sevOfScore(r.low) === name).map((r) => r.value));
        findings.push("Most incidents score " + top.low + " to " + top.high + ": " + plural(top.value, "incident") + ", " + pct(top.value, total) + " of the total.");
        findings.push(pct(band("LOW"), total) + " are Low (below 200), " + pct(band("MEDIUM"), total) + " Medium, " + pct(band("HIGH"), total) + " High and " + pct(band("CRITICAL"), total) + " Critical (600 or more).");
        const highest = rows[rows.length - 1];
        findings.push("The highest bucket is " + highest.low + " to " + highest.high + " with " + plural(highest.value, "incident") + ".");
    }
    return {
        read: [
            "The score of an incident is the sum of the weights of every action in it, so it has no fixed ceiling. Each bar groups incidents in steps of 100 points, and its color is the severity that range falls in.",
            "A distribution weighted to the left is mostly small events. A tail on the right is the rare and serious part, and that is the part to read first."
        ],
        findings,
        table: { head: ["Score range", "Severity", "Incidents", "Share"], num: [2, 3], rows: rows.map((r) => [r.low + " – " + r.high, sevName(sevOfScore(r.low)), fmtNum(r.value), pct(r.value, total)]) }
    };
}

// ---------- Duration ----------
// rows: stats.durationBySeverity -> [{ sev, count, avg, median }]

export function durationExplain(rows) {
    const used = rows.filter((r) => r.count);
    const findings = [];
    if (used.length) {
        const longest = used.slice().sort((a, b) => b.avg - a.avg)[0];
        findings.push(sevName(longest.sev) + " incidents last the longest: " + fmtDuration(longest.avg) + " on average (median " + fmtDuration(longest.median) + ").");
        used.forEach((r) => {
            if (r.median > 0 && r.avg > r.median * 1.5) findings.push(sevName(r.sev) + ": the average (" + fmtDuration(r.avg) + ") is well above the median (" + fmtDuration(r.median) + "), so a few long incidents pull it up.");
        });
    }
    return {
        read: [
            "Duration is the time between the first and the last event of an incident. A short incident is one burst of activity; a long one means the same identity kept going.",
            "The bar is the average. The median beside it is the middle value, which a few extreme incidents do not move, so comparing the two shows whether outliers are involved."
        ],
        findings,
        table: { head: ["Severity", "Incidents", "Average", "Median"], num: [1, 2, 3], rows: rows.map((r) => [sevName(r.sev), fmtNum(r.count), r.count ? fmtDuration(r.avg) : "–", r.count ? fmtDuration(r.median) : "–"]) }
    };
}

// ---------- Techniques by severity ----------
// data: stats.techniqueSeverity -> { rows: [{ technique, total, counts }] }

export function severityMatrixExplain(data) {
    const findings = [];
    if (data.rows.length) {
        const top = data.rows[0];
        const dominant = SEVERITIES.slice().sort((a, b) => (top.counts[b] || 0) - (top.counts[a] || 0))[0];
        findings.push(top.technique + " appears most (" + plural(top.total, "time") + "), and its incidents are mostly " + sevName(dominant) + " (" + (top.counts[dominant] || 0) + ").");
        const reachCritical = data.rows.filter((r) => r.counts.CRITICAL > 0).map((r) => r.technique);
        findings.push(reachCritical.length ? "Techniques that reached Critical: " + reachCritical.join(", ") + "." : "No technique reached Critical in this range.");
        const mild = data.rows.filter((r) => !r.counts.CRITICAL && !r.counts.HIGH).map((r) => r.technique);
        if (mild.length) findings.push(mild.join(", ") + (mild.length === 1 ? " stays" : " stay") + " at Medium or Low: noisy, rarely serious.");
    }
    return {
        read: [
            "Each row is a technique and each column a severity. A tinted cell holds how many incidents with that technique ended at that severity; the darker the cell, the more.",
            "Reading across a row tells you how serious a technique tends to be. A technique whose weight sits in the High and Critical columns is the one to watch, even if it is not the most frequent."
        ],
        findings
    };
}

// ---------- One entity: score over time ----------
// items: the incidents of an address or a user

export function timelineExplain(items) {
    const list = items.slice().sort((a, b) => a.timestamp - b.timestamp);
    const findings = [];
    if (list.length) {
        const scores = list.map((i) => Number(i.globalScore) || 0);
        const peak = list.reduce((a, b) => ((Number(b.globalScore) || 0) > (Number(a.globalScore) || 0) ? b : a));
        const day = (t) => shortDate(new Date(Number(t) * 1000));
        findings.push(plural(list.length, "incident") + " between " + day(list[0].timestamp) + " and " + day(list[list.length - 1].timestamp) + ".");
        findings.push("The highest score is " + fmtNum(peak.globalScore) + " (" + sevName(peak.severity) + ") on " + day(peak.timestamp) + ".");
        if (list.length >= 4) {
            const half = Math.floor(list.length / 2);
            const first = sum(scores.slice(0, half)) / half;
            const second = sum(scores.slice(half)) / (list.length - half);
            const change = first ? ((second - first) / first) * 100 : 0;
            findings.push(Math.abs(change) < 10
                ? "Scores are steady over time: the later incidents average about the same as the earlier ones."
                : "The later incidents average " + Math.abs(Math.round(change)) + "% " + (change > 0 ? "higher" : "lower") + " than the earlier ones." + (change > 0 ? " Rising scores mean the activity is getting more serious." : ""));
        }
        const serious = list.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").length;
        findings.push(serious ? plural(serious, "incident") + (serious === 1 ? " is" : " are") + " Critical or High." : "None of the incidents is Critical or High.");
    }
    return {
        read: [
            "Each dot is one incident: further right is later, higher is a bigger risk score. The color is its severity, and the tinted bands are the score thresholds that decide it.",
            "Select a dot to open the incident. A cluster of dots close together is a burst of activity; a line that climbs from band to band is the interesting shape."
        ],
        findings,
        table: {
            head: ["When (UTC)", "Severity", "Score", "Techniques"], num: [2],
            rows: list.slice().reverse().map((i) => [new Date(Number(i.timestamp) * 1000).toISOString().replace("T", " ").slice(0, 16), sevName(i.severity), fmtNum(i.globalScore), (i.mitreTechniques || []).join(", ")])
        }
    };
}

// ---------- One entity: who or what it is tied to ----------
// rows: [{ name, count, maxScore }], kind: what the rows are ("ip" or "user")

export function relatedExplain(kind, rows) {
    const findings = [];
    if (rows.length) {
        const label = kind === "ip" ? "address" : "IAM user";
        findings.push(rows.length === 1 ? "Only one " + label + " is involved: " + rows[0].name + "." : rows.length + (kind === "ip" ? " IAM users" : " addresses") + " are involved; " + rows[0].name + " has the most incidents (" + rows[0].count + ").");
        if (rows.length > 1) findings.push(kind === "ip"
            ? "More than one identity acted from this address. That is common behind a shared office or VPN, but it can also mean the same machine is using several accounts."
            : "This identity acted from more than one address. That is normal for someone who moves between networks, and worth a look if the addresses are in different countries.");
    }
    return {
        read: [kind === "ip" ? "The IAM users whose credentials made calls from this address, with the number of incidents each one took part in." : "The source addresses this identity used when it made the calls, with the number of incidents from each."],
        findings,
        table: { head: [kind === "ip" ? "IAM user" : "Source IP", "Incidents", "Highest score"], num: [1, 2], rows: rows.map((r) => [entityLink(kind === "ip" ? "user" : "ip", r.name, { mono: kind !== "ip" }), fmtNum(r.count), fmtNum(r.maxScore)]) }
    };
}

// ---------- Response page: mitigation by technique ----------
// rows: stats.mitigationByTechnique -> [{ technique, total, mitigated }]

export function responseTechniqueExplain(rows) {
    const findings = [];
    const used = rows.filter((r) => r.total);
    if (used.length) {
        const withAuto = used.filter((r) => r.mitigated > 0);
        const without = used.filter((r) => r.mitigated === 0);
        if (withAuto.length) findings.push(withAuto.map((r) => r.technique + " " + pct(r.mitigated, r.total)).join(", ") + " of incidents were mitigated automatically.");
        if (without.length) findings.push(without.map((r) => r.technique).join(", ") + (without.length === 1 ? " has" : " have") + " no automatic response today, so every one of those incidents is left to a person.");
    }
    return {
        read: [
            "Each bar is a technique and the share of its incidents where an automatic response ran. Only logging (T1562.008) and key (T1485) actions have a response today.",
            "T1562.008 will not reach 100% even when everything works: changing a trail's settings carries the same technique but is alert-only."
        ],
        findings,
        table: { head: ["Technique", "Name", "Incidents", "Mitigated", "Rate"], num: [2, 3, 4], rows: rows.map((r) => [techChip(r.technique), techName(r.technique) || "", fmtNum(r.total), fmtNum(r.mitigated), r.total ? pct(r.mitigated, r.total) : "–"]) }
    };
}
