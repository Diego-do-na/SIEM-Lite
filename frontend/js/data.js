// Data layer: one place that knows the endpoints, and a memo keyed by the data version
// (lastIncidentAt). Switching tabs or time ranges is instant, and nothing is fetched again
// until the API reports a new incident, which matches how the API caches on its side.

import { api } from "./api.js";
import { SEVERITIES, dayKey } from "./dom.js";

export const version = { current: null };
const memo = new Map();

export function clearMemo() {
    memo.clear();
}

function memoized(key, loader) {
    const hit = memo.get(key);
    if (hit && hit.version === version.current) return hit.promise;
    const promise = loader().catch((err) => {
        memo.delete(key);
        throw err;
    });
    memo.set(key, { version: version.current, promise });
    return promise;
}

// The day series always covers the last `n` UTC days, with zeros where nothing happened
function fillDays(rows, n) {
    const byDay = new Map(rows.map((r) => [r.day, r]));
    const out = [];
    const today = Date.now();
    for (let i = n - 1; i >= 0; i--) {
        const day = dayKey(today - i * 86400000);
        const row = byDay.get(day) || {};
        const item = { day, total: 0 };
        SEVERITIES.forEach((s) => {
            item[s] = Number(row[s] || 0);
            item.total += item[s];
        });
        out.push(item);
    }
    return out;
}

// One 90-day call feeds the KPIs, their trend against the previous period, and the chart for 7/30/90 days
export const trend = () => memoized("trend", async () => {
    const res = await api("/analytics/severity-trend?days=90");
    return { days: fillDays(res.data, 90), generatedAt: res.generatedAt, cached: res.cached };
});

export const mitre = (days) => memoized("mitre" + days, () => api("/analytics/mitre-techniques?days=" + days));
export const topIps = (days) => memoized("ips" + days, () => api("/analytics/top-ips?days=" + days));
export const scores = (days) => memoized("scores" + days, () => api("/analytics/score-distribution?days=" + days));
export const latest = (limit) => memoized("latest" + limit, () => api("/incidents?limit=" + limit));
// The statistics that the four reports do not cover (activity by hour, tactics, users, mitigation, duration)
// are computed in the browser from the most recent incidents of the range: up to 6 pages of 100, fetched
// one after another and memoized by data version like everything else
const SAMPLE_PAGE = 100;
const SAMPLE_PAGES = 6;

export const sample = (days) => memoized("sample" + days, async () => {
    const from = Math.floor(Date.now() / 1000) - days * 86400;
    let items = [];
    let cursor = null;
    for (let page = 0; page < SAMPLE_PAGES; page++) {
        const params = new URLSearchParams({ limit: String(SAMPLE_PAGE), from: String(from) });
        if (cursor) params.set("cursor", cursor);
        const res = await incidents(params);
        items = items.concat(res.items);
        cursor = res.nextCursor;
        if (!cursor) break;
    }
    return { items, truncated: Boolean(cursor), days };
});

export const health = () => api("/health", { auth: false });
export const stats = () => api("/stats");

export function incidents(params) {
    return api("/incidents?" + params.toString());
}

export function incident(severity, timestamp) {
    return api("/incidents/" + encodeURIComponent(severity) + "/" + encodeURIComponent(timestamp));
}

// Totals per severity for the last `n` days and for the `n` days before them (only when the 90 days cover both)
export function summarize(days90, n) {
    const sum = (rows) => rows.reduce((acc, r) => {
        SEVERITIES.forEach((s) => { acc[s] += r[s]; });
        acc.total += r.total;
        return acc;
    }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 });
    const current = days90.slice(-n);
    const previous = n * 2 <= days90.length ? days90.slice(-2 * n, -n) : null;
    return { rows: current, now: sum(current), before: previous ? sum(previous) : null };
}
