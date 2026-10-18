// Demo data for the dashboard, answered through the same paths as the real API.
// Open the page with ?mock=1 (also ?mock=empty for no incidents, ?mock=error for failing reports).
// Generated with a fixed seed, so the same numbers appear every time.

import { ApiError } from "./api.js";

const ACCOUNT = "123456789012";
const PEOPLE = [
    { user: "svc-deploy", ip: "203.0.113.42" },
    { user: "j.wilson", ip: "198.51.100.17" },
    { user: "svc-backup", ip: "192.0.2.86" },
    { user: "m.rodriguez", ip: "203.0.113.108" },
    { user: "admin01", ip: "198.51.100.230" }
];
const BANDS = { LOW: [20, 199], MEDIUM: [200, 399], HIGH: [400, 599], CRITICAL: [600, 880] };
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const TECHNIQUES = {
    "T1562.008": { actions: ["StopLogging", "UpdateTrail"], response: "CloudTrail logging restarted" },
    "T1562.007": { actions: ["AuthorizeSecurityGroupIngress", "CreateSecurityGroup"], response: null },
    "T1485": { actions: ["DisableKey", "ScheduleKeyDeletion"], response: "KMS key re-enabled" },
    "T1110": { actions: ["ListAccessKeys", "GetUser", "AttachUserPolicy"], response: null },
    "T1078.004": { actions: ["ConsoleLogin", "GetCallerIdentity"], response: null },
    "T1530": { actions: ["GetObject", "ListBuckets"], response: null }
};
const TECH_WEIGHTS = ["T1110", "T1110", "T1078.004", "T1078.004", "T1530", "T1562.007", "T1562.008", "T1485"];

let mode = "1";
let incidents = [];
let built = false;

function rng(seed) {
    let s = seed;
    return () => {
        s = (s + 0x6D2B79F5) | 0;
        let t = Math.imul(s ^ (s >>> 15), 1 | s);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (rand, n) => Array.from({ length: n }, () => Math.floor(rand() * 16).toString(16)).join("");

function build() {
    const rand = rng(20261018);
    const pick = (list) => list[Math.floor(rand() * list.length)];
    const now = Math.floor(Date.now() / 1000);
    const list = [];

    function make(ts, severity, forced) {
        const [lo, hi] = BANDS[severity];
        const score = Math.round(lo + rand() * (hi - lo));
        const person = pick(PEOPLE);
        const main = forced || pick(TECH_WEIGHTS);
        const techniques = rand() < 0.3 ? [main, pick(TECH_WEIGHTS)].filter((t, i, a) => a.indexOf(t) === i).sort() : [main];
        const dur = 40 + Math.floor(rand() * 600);
        const critical = techniques.some((t) => TECHNIQUES[t].response);
        const response = critical && (severity === "CRITICAL" || severity === "HIGH");
        const actions = {};
        techniques.forEach((t) => TECHNIQUES[t].actions.slice(0, 1 + Math.floor(rand() * 3)).forEach((a) => { actions[a] = 1 + Math.floor(rand() * 6); }));
        return {
            incidentId: hex(rand, 8) + "-" + hex(rand, 4) + "-" + hex(rand, 4) + "-" + hex(rand, 4) + "-" + hex(rand, 12),
            severity, timestamp: ts, globalScore: score, sourceIPAddress: person.ip,
            userIdentity: "arn:aws:iam::" + ACCOUNT + ":user/" + person.user,
            mitreTechniques: techniques, duration: dur, firstSeen: ts - dur, lastSeen: ts,
            responseTaken: response, _actions: actions
        };
    }

    // One critical incident in the last hour, so the table opens with something to look at
    list.push(make(now - 540, "CRITICAL", "T1562.008"));
    for (let d = 0; d < 90; d++) {
        const weekday = new Date((now - d * 86400) * 1000).getUTCDay();
        const base = weekday === 0 || weekday === 6 ? 5 : 12;
        const count = Math.round(base + rand() * 8 + (d % 23 === 0 ? 14 : 0));
        for (let k = 0; k < count; k++) {
            const r = rand();
            const severity = r < 0.04 ? "CRITICAL" : r < 0.17 ? "HIGH" : r < 0.52 ? "MEDIUM" : "LOW";
            const ts = now - d * 86400 - Math.floor(rand() * 86400) - (d === 0 ? 1800 : 0);
            list.push(make(ts, severity));
        }
    }
    list.sort((a, b) => b.timestamp - a.timestamp || SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
    return list;
}

export function configure(m) {
    mode = m;
    if (!built) {
        incidents = mode === "empty" ? [] : build();
        built = true;
    }
}

const summarize = (i) => ({
    incidentId: i.incidentId, severity: i.severity, timestamp: i.timestamp, globalScore: i.globalScore,
    sourceIPAddress: i.sourceIPAddress, userIdentity: i.userIdentity, mitreTechniques: i.mitreTechniques,
    duration: i.duration, responseTaken: i.responseTaken
});

function detail(i) {
    const user = i.userIdentity.split("/").pop();
    const names = Object.keys(i._actions);
    const actionCounts = {};
    const total = i.globalScore;
    const weights = names.map((n) => i._actions[n]);
    const wsum = weights.reduce((a, b) => a + b, 0) || 1;
    names.forEach((n, idx) => {
        actionCounts[n] = { count: i._actions[n], score: Math.round((weights[idx] / wsum) * total), awsRegion: "us-east-1", eventSource: "aws.demo" };
    });
    const tech = TECHNIQUES[i.mitreTechniques[0]];
    return {
        ...summarize(i), firstSeen: i.firstSeen, lastSeen: i.lastSeen, actionCounts, configChanges: {},
        defensiveActions: i.responseTaken && tech.response ? [{ action: "remediate", success: true, detail: tech.response }] : [],
        insights: user + " made " + names.reduce((n, a) => n + i._actions[a], 0) + " API calls from " + i.sourceIPAddress + ", including " + names.join(", ") + ".\n\n"
            + "The sequence is consistent with MITRE technique " + i.mitreTechniques[0] + ". Intent is not confirmed; the score reflects the weight of the actions seen in a 15 minute window.\n\n"
            + (i.responseTaken ? "The automated response restored the affected resource. Validate the activity with the owner of the account and review recent credentials before closing the incident."
                : "No automated response was needed. Review the activity with the owner of the account if it is unexpected.")
    };
}

function windowStats(since) {
    const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 };
    incidents.forEach((i) => { if (i.timestamp >= since) { out[i.severity]++; out.total++; } });
    return out;
}

function analytics(report, days) {
    const since = Math.floor(Date.now() / 1000) - days * 86400;
    const inRange = incidents.filter((i) => i.timestamp >= since);
    if (report === "severity-trend") {
        const byDay = {};
        inRange.forEach((i) => {
            const day = new Date(i.timestamp * 1000).toISOString().slice(0, 10);
            byDay[day] = byDay[day] || { day, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
            byDay[day][i.severity]++;
        });
        return Object.values(byDay).sort((a, b) => a.day.localeCompare(b.day));
    }
    if (report === "top-ips") {
        const by = {};
        inRange.forEach((i) => {
            by[i.sourceIPAddress] = by[i.sourceIPAddress] || { ip: i.sourceIPAddress, incidents: 0, maxScore: 0 };
            by[i.sourceIPAddress].incidents++;
            by[i.sourceIPAddress].maxScore = Math.max(by[i.sourceIPAddress].maxScore, i.globalScore);
        });
        return Object.values(by).sort((a, b) => b.incidents - a.incidents).slice(0, 10);
    }
    if (report === "mitre-techniques") {
        const by = {};
        inRange.forEach((i) => i.mitreTechniques.forEach((t) => { by[t] = (by[t] || 0) + 1; }));
        return Object.entries(by).map(([technique, n]) => ({ technique, incidents: n })).sort((a, b) => b.incidents - a.incidents).slice(0, 10);
    }
    if (report === "score-distribution") {
        const by = {};
        inRange.forEach((i) => {
            const low = Math.floor(i.globalScore / 100) * 100;
            by[low] = (by[low] || 0) + 1;
        });
        return Object.entries(by).map(([low, n]) => ({ bucket: low + "-" + (Number(low) + 99), incidents: n })).sort((a, b) => parseInt(a.bucket, 10) - parseInt(b.bucket, 10));
    }
    throw new ApiError("Unknown report", 404);
}

function list(params) {
    const limit = Math.min(100, Math.max(1, Number(params.get("limit")) || 50));
    const sev = (params.get("severity") || "").toUpperCase();
    const from = params.has("from") ? Number(params.get("from")) : null;
    const to = params.has("to") ? Number(params.get("to")) : null;
    const ip = params.get("ip") || "";
    const user = (params.get("user") || "").toLowerCase();
    const technique = params.get("technique") || "";
    const start = params.get("cursor") ? Number(atob(params.get("cursor"))) : 0;
    const matches = incidents.filter((i) =>
        (!sev || i.severity === sev) && (from === null || i.timestamp >= from) && (to === null || i.timestamp <= to)
        && (!ip || i.sourceIPAddress.startsWith(ip)) && (!user || i.userIdentity.toLowerCase().includes(user))
        && (!technique || i.mitreTechniques.includes(technique)));
    const page = matches.slice(start, start + limit);
    return { items: page.map(summarize), nextCursor: start + limit < matches.length ? btoa(String(start + limit)) : null };
}

export async function handle(path) {
    await sleep(120 + Math.random() * 220);
    const url = new URL(path, "http://demo.local");
    const parts = url.pathname.split("/").filter(Boolean);
    const now = Math.floor(Date.now() / 1000);

    if (parts[0] === "health") return { status: "ok", time: now };
    if (parts[0] === "stats") {
        return {
            generatedAt: now, lastIncidentAt: incidents.length ? incidents[0].timestamp : null, cached: false,
            windows: { "24h": windowStats(now - 86400), "7d": windowStats(now - 7 * 86400), all: windowStats(0) }
        };
    }
    if (parts[0] === "analytics" && parts[1]) {
        if (mode === "error" && parts[1] === "mitre-techniques") throw new ApiError("Query timed out, retry", 504);
        const days = Number(url.searchParams.get("days") || 30);
        return { report: parts[1], days, generatedAt: now, version: incidents.length ? incidents[0].timestamp : null, cached: false, data: analytics(parts[1], days) };
    }
    if (parts[0] === "incidents" && parts.length === 3) {
        const found = incidents.find((i) => i.severity === parts[1] && String(i.timestamp) === parts[2]);
        if (!found) throw new ApiError("Incident not found", 404);
        return detail(found);
    }
    if (parts[0] === "incidents") return list(url.searchParams);
    throw new ApiError("Not found", 404);
}
