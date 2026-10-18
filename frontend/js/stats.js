// Statistics computed in the browser from a sample of incidents (the list endpoint already returns
// severity, time, score, IP, user, techniques, duration and whether a response ran). Pure functions,
// no DOM: the views only draw what these return.

import { SEVERITIES, userShort } from "./dom.js";
import { tacticOf } from "./mitre.js";

export { tacticOf };

export const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
// Rows of the heatmap start on Monday
const WEEK_ORDER = [1, 2, 3, 4, 5, 6, 0];

const sum = (list) => list.reduce((n, x) => n + x, 0);
const sorted = (list) => list.slice().sort((a, b) => a - b);

export function percentile(values, p) {
    if (!values.length) return 0;
    const s = sorted(values);
    return s[Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1))];
}

const count = (map, key) => map.set(key, (map.get(key) || 0) + 1);

// Incidents per weekday and hour (UTC). rows are Monday to Sunday, cells are the 24 hours
export function activity(items) {
    const grid = Array.from({ length: 7 }, () => Array(24).fill(0));
    items.forEach((i) => {
        const d = new Date(Number(i.timestamp) * 1000);
        grid[d.getUTCDay()][d.getUTCHours()]++;
    });
    const rows = WEEK_ORDER.map((day) => ({ label: WEEKDAYS[day], cells: grid[day] }));
    const hours = Array.from({ length: 24 }, (_, h) => sum(grid.map((row) => row[h])));
    const days = WEEKDAYS.map((_, day) => sum(grid[day]));
    return { rows, max: Math.max(0, ...rows.flatMap((r) => r.cells)), hours, days };
}

export function summary(items) {
    const total = items.length;
    const mitigated = items.filter((i) => i.responseTaken).length;
    const durations = items.map((i) => Number(i.duration) || 0);
    const scores = items.map((i) => Number(i.globalScore) || 0);
    const ips = new Map();
    const users = new Map();
    items.forEach((i) => {
        count(ips, i.sourceIPAddress);
        count(users, userShort(i.userIdentity));
    });
    const act = activity(items);
    const peakHour = total ? act.hours.indexOf(Math.max(...act.hours)) : null;
    const peakDay = total ? act.days.indexOf(Math.max(...act.days)) : null;
    const topUser = [...users.entries()].sort((a, b) => b[1] - a[1])[0];
    return {
        total, mitigated,
        mitigationRate: total ? mitigated / total : null,
        avgDuration: total ? sum(durations) / total : 0,
        medianDuration: percentile(durations, 0.5),
        medianScore: percentile(scores, 0.5),
        p90Score: percentile(scores, 0.9),
        maxScore: Math.max(0, ...scores),
        ips: ips.size,
        repeatIps: [...ips.values()].filter((n) => n >= 2).length,
        users: users.size,
        topUser: topUser ? topUser[0] : "",
        peakHour,
        peakDay: peakDay === null ? null : WEEKDAYS[peakDay]
    };
}

// Incidents per MITRE tactic; an incident with two techniques of the same tactic counts once
export function byTactic(items) {
    const map = new Map();
    items.forEach((i) => new Set((i.mitreTechniques || []).map(tacticOf)).forEach((t) => count(map, t)));
    return [...map.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
}

export function topUsers(items, limit = 8) {
    const map = new Map();
    items.forEach((i) => {
        const name = userShort(i.userIdentity);
        const row = map.get(name) || { user: name, count: 0, maxScore: 0, ips: new Set() };
        row.count++;
        row.maxScore = Math.max(row.maxScore, Number(i.globalScore) || 0);
        row.ips.add(i.sourceIPAddress);
        map.set(name, row);
    });
    return [...map.values()].sort((a, b) => b.count - a.count || b.maxScore - a.maxScore).slice(0, limit)
        .map((r) => ({ user: r.user, count: r.count, maxScore: r.maxScore, ips: r.ips.size }));
}

export function mitigationBySeverity(items) {
    return SEVERITIES.map((sev) => {
        const rows = items.filter((i) => i.severity === sev);
        return { sev, total: rows.length, mitigated: rows.filter((i) => i.responseTaken).length };
    });
}

export function durationBySeverity(items) {
    return SEVERITIES.map((sev) => {
        const d = items.filter((i) => i.severity === sev).map((i) => Number(i.duration) || 0);
        return { sev, count: d.length, avg: d.length ? sum(d) / d.length : 0, median: percentile(d, 0.5) };
    });
}

// Technique by severity, the most frequent techniques first
export function techniqueSeverity(items, limit = 8) {
    const map = new Map();
    items.forEach((i) => (i.mitreTechniques || []).forEach((t) => {
        const row = map.get(t) || { technique: t, total: 0, counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } };
        row.total++;
        row.counts[i.severity] = (row.counts[i.severity] || 0) + 1;
        map.set(t, row);
    }));
    const rows = [...map.values()].sort((a, b) => b.total - a.total).slice(0, limit);
    return { rows, max: Math.max(0, ...rows.flatMap((r) => SEVERITIES.map((s) => r.counts[s]))) };
}
