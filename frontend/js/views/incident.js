// One incident as a page of its own: #/incidents/<SEVERITY>/<timestamp>.
// A big risk score inside a ring in the color of the severity, then what happened and how the score was built.
// Everything shown comes from the incident record; nothing is inferred beyond the tables in js/mitre.js.

import * as data from "../data.js";
import { el, svg, icon, ICONS, sevBadge, sevClass, sevOfScore, SEVERITIES, techName, userShort, accountOf, shortDate, clock, fmtDuration, fmtNum, countUp, plural } from "../dom.js";
import { actionInfo, tacticOf } from "../mitre.js";
import { techChip } from "./ui.js";

// The ring is full at this score. Scores above it keep the ring full; the number is never capped
const SCALE = 1000;
const BANDS = [[0, 200, "LOW"], [200, 400, "MEDIUM"], [400, 600, "HIGH"], [600, 1000, "CRITICAL"]];
const SIZE = 260;
const MID = SIZE / 2;
const R = 100;
const R_BAND = 119;
const CIRC = 2 * Math.PI * R;
const CIRC_BAND = 2 * Math.PI * R_BAND;

function ring(score, severity) {
    const fraction = Math.min(1, Math.max(score > 0 ? 0.012 : 0, score / SCALE));
    const turn = `rotate(-90 ${MID} ${MID})`;
    const bands = BANDS.map(([from, to, sev]) => {
        const length = ((to - from) / SCALE) * CIRC_BAND - 3;
        return svg("circle", {
            class: "ring-band" + (sev === severity ? " on" : ""), cx: MID, cy: MID, r: R_BAND, transform: turn,
            "stroke-dasharray": length + " " + CIRC_BAND, "stroke-dashoffset": String(-(from / SCALE) * CIRC_BAND - 1.5),
            vars: { "--c": "var(--sev-" + sev.toLowerCase() + ")" }
        });
    });
    // Tick marks where the next severity starts, with the number beside them
    const ticks = [200, 400, 600].flatMap((value) => {
        const angle = (value / SCALE) * 2 * Math.PI - Math.PI / 2;
        const at = (radius) => [MID + Math.cos(angle) * radius, MID + Math.sin(angle) * radius];
        const [x1, y1] = at(R - 11);
        const [x2, y2] = at(R + 11);
        const [tx, ty] = at(R_BAND + 14);
        return [
            svg("line", { class: "ring-tick", x1, y1, x2, y2 }),
            svg("text", { class: "ring-tick-label", x: tx, y: ty, "text-anchor": "middle", "dominant-baseline": "central", text: String(value) })
        ];
    });
    return svg("svg", { class: "ring", viewBox: `0 0 ${SIZE} ${SIZE}`, role: "img", "aria-label": "Risk score " + score + ", " + severity.toLowerCase() + " severity" }, [
        ...bands,
        svg("circle", { class: "ring-track", cx: MID, cy: MID, r: R }),
        severity === "CRITICAL" ? svg("circle", { class: "ring-pulse", cx: MID, cy: MID, r: R }) : null,
        svg("circle", { class: "ring-progress", cx: MID, cy: MID, r: R, transform: turn, "stroke-dasharray": (fraction * CIRC) + " " + CIRC }),
        ...ticks
    ]);
}

function block(title, sub, children, className = "") {
    return el("section", { class: "card panel inc-block " + className }, [
        el("header", { class: "panel-head" }, [el("div", {}, [el("h2", { text: title }), sub ? el("p", { class: "sub", text: sub }) : null])]),
        ...[].concat(children)
    ]);
}

function actionRows(item) {
    const rows = [];
    for (const group of [item.actionCounts || {}, item.configChanges || {}]) {
        Object.entries(group).forEach(([name, d]) => {
            const count = d && d.count !== undefined ? Number(d.count) : 1;
            const score = d && d.score !== undefined ? Number(d.score) : actionInfo(name).weight * count;
            rows.push({ name, count, score, region: d && d.awsRegion, source: d && d.eventSource });
        });
    }
    return rows.sort((a, b) => b.score - a.score);
}

function copyButton(text, label) {
    const button = el("button", { class: "btn small", type: "button" }, [label]);
    button.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(text);
            button.textContent = "Copied";
        } catch (e) {
            button.textContent = "Copy not available";
        }
        setTimeout(() => { button.textContent = label; }, 1600);
    });
    return button;
}

function hero(item, rows, ok, failed) {
    const main = rows[0] ? rows[0].name : "";
    const info = actionInfo(main);
    const technique = rows[0] ? info.technique : (item.mitreTechniques || [])[0];
    const number = el("span", { class: "ring-number", text: "0" });
    const color = "var(--sev-" + sevClass(item.severity) + ")";
    const ringBox = el("div", { class: "ring-box", vars: { "--c": color } }, [
        ring(Number(item.globalScore), item.severity),
        el("div", { class: "ring-center" }, [el("span", { class: "ring-cap", text: "Risk score" }), number, el("span", { class: "ring-sev", text: item.severity.charAt(0) + item.severity.slice(1).toLowerCase() })])
    ]);
    countUp(number, Number(item.globalScore), { ms: 1300 });

    const status = ok.length
        ? el("span", { class: "resp on" }, [icon(ICONS.shieldCheck), "Mitigated automatically"])
        : failed.length ? el("span", { class: "resp bad" }, [icon(ICONS.minus), "Automated response failed"])
            : el("span", { class: "resp" }, [icon(ICONS.minus), "No automated response"]);

    return el("section", { class: "card inc-hero", vars: { "--c": color } }, [
        ringBox,
        el("div", { class: "inc-hero-main" }, [
            el("div", { class: "inc-eyebrow" }, [sevBadge(item.severity), status]),
            el("h1", { text: techName(technique) || "Security incident" }),
            el("p", { class: "inc-lede", text: info && rows[0] ? info.what : "Activity recorded by the detection rules." }),
            el("dl", { class: "inc-facts" }, [
                ["IAM user", userShort(item.userIdentity)], ["Source IP", item.sourceIPAddress], ["Region", rows.map((r) => r.region).find(Boolean) || item.awsRegion || ""],
                ["When", shortDate(new Date(Number(item.timestamp) * 1000)) + " · " + clock(item.timestamp) + " UTC"]
            ].filter(([, v]) => v).map(([k, v]) => el("div", {}, [el("dt", { text: k }), el("dd", { text: String(v) })]))),
            el("div", { class: "inc-chips" }, (item.mitreTechniques || []).map((t) => techChip(t, { showName: true })))
        ])
    ]);
}

function happened(item, rows) {
    const total = rows.reduce((n, r) => n + r.count, 0);
    const top = rows[0];
    const paragraphs = [];
    paragraphs.push(`${userShort(item.userIdentity)} made ${plural(total, "API call")} from ${item.sourceIPAddress}, between ${clock(item.firstSeen)} and ${clock(item.lastSeen)} UTC (${fmtDuration(item.duration)}).`);
    if (top) {
        const share = Math.round((top.score / Math.max(1, rows.reduce((n, r) => n + r.score, 0))) * 100);
        paragraphs.push(`${top.name} weighs the most: ${share}% of the score. ${actionInfo(top.name).what}`);
    }
    return block("What happened", "Facts from the event record", [el("div", { class: "inc-text" }, paragraphs.map((p) => el("p", { text: p })))]);
}

function breakdown(item, rows) {
    const sum = rows.reduce((n, r) => n + r.score, 0);
    const top = Math.max(1, ...rows.map((r) => r.score));
    const list = el("ol", { class: "inc-actions" }, rows.map((r, index) => {
        const info = actionInfo(r.name);
        return el("li", { vars: { "--i": String(index) } }, [
            el("div", { class: "inc-action-head" }, [
                el("b", { class: "mono", text: r.name }),
                info.soar ? el("span", { class: "pill soar", title: "The response Lambda answers this action: " + info.soar, text: "Auto-response" }) : null,
                el("span", { class: "inc-points", text: fmtNum(r.score) })
            ]),
            el("p", { class: "inc-action-what", text: info.what }),
            el("div", { class: "bar-track" }, [el("div", { class: "bar-fill", vars: { "--w": Math.max(2, (r.score / top) * 100) + "%", "--bar": "var(--sev-" + sevClass(item.severity) + ")", "--i": String(index) } })]),
            el("p", { class: "inc-action-meta", text: [
                plural(r.count, "call") + " × " + info.weight + " points", r.region, r.source
            ].filter(Boolean).join(" · ") })
        ]);
    }));
    const foot = el("p", { class: "inc-formula" }, [
        el("span", { text: "Sum of actions" }), el("b", { text: fmtNum(sum) }),
        el("span", { class: "muted", text: sum === Number(item.globalScore) ? "= risk score" : "Risk score " + fmtNum(item.globalScore) + " (the behavior baseline can scale it)" })
    ]);
    const scale = el("div", { class: "inc-scale", role: "img", "aria-label": "Severity thresholds" }, SEVERITIES.slice().reverse().map((s, i) => {
        const [from] = BANDS[i];
        return el("span", { class: s === item.severity ? "on" : "", vars: { "--c": "var(--sev-" + sevClass(s) + ")" } }, [el("i"), s.charAt(0) + s.slice(1).toLowerCase(), el("small", { text: from === 0 ? "1+" : from + "+" })]);
    }));
    return block("How the score was built", "Each action has a fixed weight; calls add up", [list, foot, scale]);
}

function triage(item) {
    const paragraphs = String(item.insights || "").split(/\n{2,}/).map((p) => p.trim()).filter(Boolean);
    return block("AI triage", "Written by Amazon Bedrock. Review before acting", [
        el("div", { class: "inc-text" }, paragraphs.length ? paragraphs.map((p) => el("p", { text: p })) : [el("p", { class: "muted", text: "No summary was generated for this incident." })])
    ]);
}

function response(item, rows) {
    const defensive = item.defensiveActions || [];
    if (!defensive.length) {
        const can = rows.some((r) => actionInfo(r.name).soar);
        return block("Automated response", "SOAR", [el("p", { class: "muted", text: can
            ? "The response ran but nothing was recorded for this incident."
            : "None of the actions in this incident has an automatic answer. Only StopLogging, DeleteTrail, DisableKey and ScheduleKeyDeletion do. Review it by hand." })]);
    }
    return block("Automated response", "What SOAR did", [el("ul", { class: "inc-response" }, defensive.map((a) => el("li", { class: a.success ? "ok" : "fail" }, [
        icon(a.success ? ICONS.shieldCheck : ICONS.close),
        el("div", {}, [
            el("b", { text: String(a.detail || a.action) }),
            el("small", { text: [a.action, a.targetResource ? userShortResource(a.targetResource) : "", a.timestamp ? clock(a.timestamp) + " UTC" : ""].filter(Boolean).join(" · ") })
        ])
    ])))]);
}

const userShortResource = (arn) => String(arn).split(":").pop();

function timeline(item) {
    const events = [{ at: Number(item.firstSeen), label: "First event recorded", kind: "" }];
    (item.defensiveActions || []).forEach((a) => {
        if (a.timestamp) events.push({ at: Number(a.timestamp), label: (a.success ? "Response: " : "Response failed: ") + String(a.detail || a.action), kind: a.success ? "ok" : "fail" });
    });
    events.push({ at: Number(item.lastSeen), label: "Last event recorded", kind: "" });
    events.sort((a, b) => a.at - b.at);
    const start = events[0].at;
    return block("Timeline", "UTC", [el("ol", { class: "inc-timeline" }, events.map((e) => el("li", { class: e.kind }, [
        el("span", { class: "tl-dot" }),
        el("div", {}, [el("b", { text: e.label }), el("small", { text: clock(e.at) + " · " + (e.at === start ? "start" : "+" + fmtDuration(e.at - start)) })])
    ])))]);
}

function details(item, rows) {
    const region = rows.map((r) => r.region).find(Boolean) || item.awsRegion || "";
    return block("Details", null, [el("dl", { class: "kv one" }, [
        ["IAM user", userShort(item.userIdentity)], ["Source IP", item.sourceIPAddress], ["AWS account", accountOf(item.userIdentity)], ["Region", region],
        ["Duration", fmtDuration(item.duration)], ["Incident ID", item.incidentId]
    ].filter(([, v]) => v).map(([k, v]) => el("div", {}, [el("dt", { text: k }), el("dd", { class: k === "Incident ID" ? "wrap" : "", text: String(v) })])))]);
}

function attack(item) {
    const list = item.mitreTechniques || [];
    return block("MITRE ATT&CK", "Select a technique to read about it", [el("ul", { class: "inc-attack" }, list.map((t) => el("li", {}, [
        techChip(t),
        el("div", {}, [el("b", { text: techName(t) }), el("small", { text: tacticOf(t) })])
    ])))]);
}

function render(item) {
    const rows = actionRows(item);
    const defensive = item.defensiveActions || [];
    const ok = defensive.filter((a) => a.success);
    const failed = defensive.filter((a) => !a.success);
    return [
        hero(item, rows, ok, failed),
        el("div", { class: "inc-layout" }, [
            el("div", { class: "inc-main" }, [happened(item, rows), breakdown(item, rows), triage(item)]),
            el("aside", { class: "inc-side" }, [response(item, rows), attack(item), timeline(item), details(item, rows)])
        ])
    ];
}

export function mount(root, ctx) {
    const [severity, stamp] = String(ctx.param || "").split("/");
    const head = (right) => el("div", { class: "inc-top" }, [
        el("a", { class: "back", href: "#/incidents", onclick: (e) => { if (ctx.canGoBack()) { e.preventDefault(); history.back(); } } }, [icon(ICONS.chevronLeft), "Back"]),
        right || null
    ]);
    const body = el("div", { class: "inc-body" });
    root.append(head(), body);
    let run = 0;

    if (!SEVERITIES.includes(severity) || !/^\d+$/.test(stamp || "")) {
        body.replaceChildren(el("div", { class: "card panel" }, [el("div", { class: "error-box" }, [el("p", { text: "This incident link is not valid." }), el("a", { class: "btn", href: "#/incidents", text: "Go to incidents" })])]));
        return { refresh() {}, destroy() {} };
    }

    async function load() {
        const mine = ++run;
        body.replaceChildren(el("div", { class: "skel", vars: { "--h": "300px" } }), el("div", { class: "skel", vars: { "--h": "260px" } }));
        try {
            const item = await data.incident(severity, stamp);
            if (mine !== run) return;
            // The record decides the severity, so a link with a wrong one still shows the right color
            if (!item.severity) item.severity = severity;
            if (SEVERITIES.indexOf(item.severity) === -1) item.severity = sevOfScore(Number(item.globalScore));
            root.replaceChildren(head(copyButton(item.incidentId || "", "Copy ID")), body);
            document.title = item.severity.charAt(0) + item.severity.slice(1).toLowerCase() + " incident · SIEM Lite";
            body.replaceChildren(...render(item));
        } catch (err) {
            if (mine !== run) return;
            const missing = err && err.status === 404;
            body.replaceChildren(el("div", { class: "card panel" }, [el("div", { class: "error-box" }, [
                el("p", { text: missing ? "This incident does not exist, or it was removed." : "Could not load this incident. " + (err && err.message ? err.message : "") }),
                missing ? el("a", { class: "btn", href: "#/incidents", text: "Go to incidents" }) : el("button", { class: "btn", type: "button", text: "Retry", onclick: load })
            ])]));
        }
    }

    load();
    // An incident does not change once written, so the live refresh leaves the page alone
    return { refresh(soft) { if (soft !== true) load(); }, destroy() { run++; } };
}
