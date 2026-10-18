// Demo data for the dashboard, answered through the same paths as the real API.
// Open the page with ?mock=1 (also ?mock=empty for no incidents, ?mock=error for failing reports).
// Generated with a fixed seed, so the same numbers appear every time.
//
// The incidents follow the real rules: the actions, weights, techniques and automatic responses come from
// js/mitre.js (a copy of the backend tables), and the score of an incident is the sum of its actions.

import { ApiError } from "./api.js";
import { ACTIONS, actionInfo } from "./mitre.js";
import { sevOfScore } from "./dom.js";

const ACCOUNT = "123456789012";
const PEOPLE = [
    { user: "svc-deploy", ip: "203.0.113.42" },
    { user: "j.wilson", ip: "198.51.100.17" },
    { user: "svc-backup", ip: "192.0.2.86" },
    { user: "m.rodriguez", ip: "203.0.113.108" },
    { user: "admin01", ip: "198.51.100.230" },
    // Several people behind one office address, and one account used from a second address (travel, VPN)
    { user: "a.torres", ip: "198.51.100.17" },
    { user: "m.rodriguez", ip: "198.51.100.17" },
    { user: "admin01", ip: "192.0.2.201" }
];
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
// Region of the activity, weighted: the system lives in Oregon, a few calls come from other regions
const REGIONS = [["us-west-2", 55], ["us-east-1", 20], ["eu-west-1", 10], ["ap-southeast-1", 7], ["sa-east-1", 5], ["eu-central-1", 3]];
const SOURCES = {
    cloudtrail: "cloudtrail.amazonaws.com", kms: "kms.amazonaws.com", ec2: "ec2.amazonaws.com", iam: "iam.amazonaws.com"
};
const sourceOf = (action) => {
    const t = (ACTIONS[action] || {}).technique;
    if (t === "T1562.008") return SOURCES.cloudtrail;
    if (t === "T1485") return SOURCES.kms;
    if (t === "T1562.007") return SOURCES.ec2;
    return SOURCES.iam;
};
// Denied calls the rules do not recognise: each adds the base weight (40) and gets the generic T1110 label
const DENIED = ["ListAccessKeys", "GetUser", "ListUsers", "GetLoginProfile", "ListAttachedUserPolicies"];

// What each severity looks like. [action, min calls, max calls]; noise adds a few denied calls on top
const SCENARIOS = {
    LOW: [
        { actions: [["RevokeSecurityGroupEgress", 1, 1]], noise: 2 },
        { actions: [["RevokeSecurityGroupIngress", 1, 1]], noise: 1 },
        { actions: [["CreateSecurityGroup", 1, 1]], noise: 0 },
        { actions: [], noise: 3, denied: [2, 4] },
        { actions: [], noise: 3, denied: [1, 3] }
    ],
    MEDIUM: [
        { actions: [["AuthorizeSecurityGroupIngress", 1, 1]], noise: 2 },
        { actions: [["UpdateTrail", 1, 1]], noise: 2 },
        { actions: [["DeleteSecurityGroup", 1, 1]], noise: 1 },
        { actions: [], noise: 0, denied: [5, 8] }
    ],
    HIGH: [
        { actions: [["StopLogging", 1, 1]], noise: 3 },
        { actions: [["DeleteTrail", 1, 1]], noise: 2 },
        { actions: [["DisableKey", 1, 1]], noise: 2 },
        { actions: [["ScheduleKeyDeletion", 1, 1]], noise: 3 }
    ],
    CRITICAL: [
        { actions: [["StopLogging", 1, 1], ["AuthorizeSecurityGroupIngress", 1, 2]], noise: 2 },
        { actions: [["DeleteTrail", 1, 1], ["ScheduleKeyDeletion", 1, 1]], noise: 2 },
        { actions: [["StopLogging", 1, 1], ["DisableKey", 1, 1]], noise: 1 },
        { actions: [["DisableKey", 1, 1], ["DeleteSecurityGroup", 1, 2], ["UpdateTrail", 1, 1]], noise: 1 }
    ]
};

let mode = "1";
let incidents = [];
let built = false;
let gen = null;
let liveTimer = null;

// Demo only: every ~20 seconds a new incident "happens", so the automatic refresh of the dashboard can be seen
const LIVE_EVERY_MS = 20000;

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

// The data is generated from a moment kept for the tab, so reloading the page (or following an incident link) shows the same incidents
function anchor() {
    const fresh = Math.floor(Date.now() / 1000);
    try {
        const saved = Number(sessionStorage.getItem("siem-mock-now"));
        if (saved && fresh - saved < 7 * 86400) return saved;
        sessionStorage.setItem("siem-mock-now", String(fresh));
    } catch (e) { /* storage blocked: the data simply changes on reload */ }
    return fresh;
}

function build() {
    const rand = rng(20261018);
    const pick = (list) => list[Math.floor(rand() * list.length)];
    const between = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));
    const now = anchor();
    const list = [];

    function region() {
        let r = rand() * 100;
        for (const [name, w] of REGIONS) { r -= w; if (r < 0) return name; }
        return REGIONS[0][0];
    }

    function make(ts, severity, scenario) {
        const plan = scenario || pick(SCENARIOS[severity]);
        const person = pick(PEOPLE);
        const calls = {};
        plan.actions.forEach(([name, lo, hi]) => { calls[name] = between(lo, hi); });
        const denied = plan.denied ? between(plan.denied[0], plan.denied[1]) : 0;
        const extra = denied || between(0, plan.noise || 0);
        for (let k = 0; k < extra; k++) { const name = pick(DENIED); calls[name] = (calls[name] || 0) + 1; }
        const home = region();
        const actions = {};
        let score = 0;
        Object.entries(calls).forEach(([name, count]) => {
            const points = actionInfo(name).weight * count;
            score += points;
            actions[name] = { count, score: points, awsRegion: ACTIONS[name] && rand() < 0.15 ? "us-west-2" : home, eventSource: sourceOf(name) };
        });
        const techniques = [...new Set(Object.keys(calls).map((a) => actionInfo(a).technique))].sort();
        // The response Lambda answers the critical actions; DeleteTrail can fail when AWS Config has no history
        const defensive = [];
        Object.keys(calls).forEach((name) => {
            const info = ACTIONS[name];
            if (!info || !info.soar) return;
            const failed = name === "DeleteTrail" && rand() < 0.2;
            defensive.push({
                action: name, success: !failed, timestamp: ts + between(2, 20),
                targetResource: name === "StopLogging" || name === "DeleteTrail" ? "arn:aws:cloudtrail:" + home + ":" + ACCOUNT + ":trail/siem-lite-trail" : "key/" + hex(rand, 8) + "-" + hex(rand, 4) + "-" + hex(rand, 4) + "-" + hex(rand, 12),
                detail: failed ? "No configuration history found in AWS Config for this trail, cannot recreate"
                    : name === "StopLogging" ? "Trail logging restarted successfully"
                        : name === "DeleteTrail" ? "Trail recreated and logging verified active"
                            : name === "DisableKey" ? "KMS key re-enabled successfully" : "KMS key deletion canceled successfully"
            });
        });
        const dur = 40 + Math.floor(rand() * 600);
        return {
            incidentId: hex(rand, 8) + "-" + hex(rand, 4) + "-" + hex(rand, 4) + "-" + hex(rand, 4) + "-" + hex(rand, 12),
            severity: sevOfScore(score), timestamp: ts, globalScore: score, sourceIPAddress: person.ip,
            userIdentity: "arn:aws:iam::" + ACCOUNT + ":user/" + person.user,
            mitreTechniques: techniques, duration: dur, firstSeen: ts - dur, lastSeen: ts,
            responseTaken: defensive.some((d) => d.success), awsRegion: home, _actions: actions, _defensive: defensive
        };
    }

    // One critical incident in the last hour, so the table opens with something to look at
    list.push(make(now - 540, "CRITICAL", SCENARIOS.CRITICAL[0]));
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
    gen = { rand, make };
    return list;
}

function addLive() {
    if (!gen) return;
    const r = gen.rand();
    const severity = r < 0.12 ? "CRITICAL" : r < 0.34 ? "HIGH" : r < 0.7 ? "MEDIUM" : "LOW";
    const now = Math.floor(Date.now() / 1000);
    const ts = incidents.length ? Math.max(now, incidents[0].timestamp + 1) : now;
    incidents.unshift(gen.make(ts, severity));
}

export function configure(m) {
    mode = m;
    if (!built) {
        incidents = mode === "empty" ? [] : build();
        built = true;
    }
    if (mode === "1" && !liveTimer) liveTimer = setInterval(addLive, LIVE_EVERY_MS);
}

// The list items carry awsRegion here so the region map can be previewed. The real list endpoint does not return it yet (planned for 1.1)
const summarize = (i) => ({
    incidentId: i.incidentId, severity: i.severity, timestamp: i.timestamp, globalScore: i.globalScore,
    sourceIPAddress: i.sourceIPAddress, userIdentity: i.userIdentity, mitreTechniques: i.mitreTechniques,
    duration: i.duration, responseTaken: i.responseTaken, awsRegion: i.awsRegion
});

function detail(i) {
    const user = i.userIdentity.split("/").pop();
    const names = Object.keys(i._actions);
    const actionCounts = {};
    names.forEach((n) => { actionCounts[n] = { ...i._actions[n] }; });
    const total = names.reduce((n, a) => n + i._actions[a].count, 0);
    const main = names.slice().sort((a, b) => i._actions[b].score - i._actions[a].score)[0];
    const failed = i._defensive.filter((d) => !d.success);
    const paragraphs = [
        "The activity matches MITRE ATT&CK " + i.mitreTechniques.join(", ") + ". The heaviest call is " + main + " from " + user + " at " + i.sourceIPAddress + ". The score adds the weight of each action: it shows how serious the actions are, not whether the intent was malicious.",
        i._defensive.length ? (failed.length ? "The automated response ran but did not finish: " + failed[0].detail + ". Manual action is needed. Confirm the state of the resource and review the credentials of " + user + "."
            : "The automated response restored the affected resource. Validate the change with the owner of " + user + " and review recent credentials before closing the incident.")
            : "No automated response applies to these actions. Review the activity with the owner of " + user + " if it is unexpected."
    ];
    return {
        ...summarize(i), firstSeen: i.firstSeen, lastSeen: i.lastSeen, actionCounts, configChanges: {},
        defensiveActions: i._defensive.map((d) => ({ ...d })), insights: paragraphs.join("\n\n")
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
