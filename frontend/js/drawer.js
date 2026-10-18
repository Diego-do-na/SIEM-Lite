// Incident detail drawer. Opens from any incident row, closes with Esc, the scrim or the close button,
// and gives focus back to the row that opened it.

import * as data from "./data.js";
import { el, icon, ICONS, sevBadge, techName, userShort, accountOf, fullDate, clock, fmtDuration, fmtNum } from "./dom.js";

let opener = null;
let run = 0;

const drawerEl = () => document.getElementById("drawer");
const scrimEl = () => document.getElementById("scrim");

export function closeDrawer() {
    run++;
    drawerEl().hidden = true;
    scrimEl().hidden = true;
    document.removeEventListener("keydown", onKey);
    if (opener && document.contains(opener)) opener.focus();
    opener = null;
}

function onKey(e) {
    if (e.key === "Escape") closeDrawer();
}

function header(title) {
    return el("div", { class: "drawer-head" }, [
        el("div", { class: "t" }, [icon(ICONS.incidents), el("span", { id: "drawer-title", text: title })]),
        el("button", { class: "icon-btn", type: "button", "aria-label": "Close details", onclick: closeDrawer }, [icon(ICONS.close)])
    ]);
}

function actionRows(i) {
    const rows = [];
    for (const group of [i.actionCounts || {}, i.configChanges || {}]) {
        Object.entries(group).forEach(([name, d]) => {
            const score = (i.actionScores && i.actionScores[name] !== undefined) ? i.actionScores[name] : (d && d.score);
            rows.push({ name, count: d && d.count !== undefined ? Number(d.count) : null, score: score === undefined ? null : Number(score) });
        });
    }
    return rows.sort((a, b) => (b.score || 0) - (a.score || 0));
}

function firstRegion(i) {
    for (const group of [i.actionCounts || {}, i.configChanges || {}]) {
        for (const d of Object.values(group)) if (d && d.awsRegion) return d.awsRegion;
    }
    return "";
}

function section(title, tag, children) {
    return el("section", { class: "d-sec" }, [el("h3", {}, [title, tag ? el("small", { text: tag }) : null]), ...children]);
}

function render(i) {
    const defensive = i.defensiveActions || [];
    const ok = defensive.filter((a) => a.success);
    const techniques = i.mitreTechniques || [];
    const title = techniques.map(techName).find(Boolean) || "Security incident";

    const callout = !defensive.length ? null : el("div", { class: "callout" + (ok.length ? "" : " warn") }, [
        icon(ICONS.shieldCheck),
        el("div", {}, [
            el("b", { text: ok.length ? "Mitigated automatically" : "Automated response did not complete" }),
            el("small", { text: defensive.map((a) => String(a.detail || a.action) + (a.success ? "" : " (failed)")).join(" · ") || "Manual review needed" })
        ])
    ]);

    const info = el("dl", { class: "kv" }, [
        ["IAM user", userShort(i.userIdentity)], ["Source IP", i.sourceIPAddress], ["AWS account", accountOf(i.userIdentity)], ["Region", firstRegion(i)]
    ].filter(([, v]) => v).map(([k, v]) => el("div", {}, [el("dt", { text: k }), el("dd", { text: String(v) })])));

    const paragraphs = String(i.insights || "").split(/\n{2,}/).map((p) => p.trim()).filter(Boolean);
    const rows = actionRows(i);
    const maxScore = Math.max(1, ...rows.map((r) => r.score || 0));

    return [
        header("Incident details"),
        el("div", { class: "drawer-body" }, [
            el("div", {}, [
                el("div", { class: "d-top" }, [sevBadge(i.severity), el("span", { class: "d-score" }, ["Risk score", el("b", { text: fmtNum(i.globalScore) })])]),
                el("h2", { class: "d-title", text: title }),
                el("p", { class: "d-id", text: i.incidentId || "" })
            ]),
            callout,
            info,
            techniques.length ? el("div", { class: "techs" }, techniques.flatMap((t) => [el("span", { class: "chip", text: t }), techName(t)])) : null,
            section("AI triage", "Generated analysis", [
                el("div", { class: "insight" }, paragraphs.length ? paragraphs.map((p) => el("p", { text: p })) : [el("p", { text: "No summary was generated for this incident." })])
            ]),
            section("Timeline", null, [
                el("dl", { class: "timeline" }, [
                    el("div", {}, [el("dt", { text: "First seen" }), el("dd", { text: clock(i.firstSeen) })]),
                    el("div", {}, [el("dt", { text: "Last seen" }), el("dd", { text: clock(i.lastSeen) })]),
                    el("div", {}, [el("dt", { text: "Duration" }), el("dd", { text: fmtDuration(i.duration) })])
                ]),
                el("div", { class: "tl-line" }),
                el("p", { class: "d-source tl-date", text: fullDate(i.timestamp) })
            ]),
            rows.length ? section("Actions breakdown", rows.reduce((n, r) => n + (r.count || 0), 0) + " source events", [
                el("table", { class: "mini-table" }, [
                    el("thead", {}, [el("tr", {}, [el("th", { text: "AWS API action" }), el("th", { class: "num", text: "Events" }), el("th", { class: "num", text: "Score" })])]),
                    el("tbody", {}, rows.map((r) => el("tr", {}, [
                        el("td", { text: r.name }),
                        el("td", { class: "num", text: r.count === null ? "" : fmtNum(r.count) }),
                        el("td", { class: "num", text: r.score === null ? "" : fmtNum(r.score) })
                    ])))
                ])
            ]) : null,
            el("p", { class: "d-source", text: "Source: AWS CloudTrail · Management events" })
        ])
    ];
}

export async function openIncident(severity, timestamp, from) {
    const myRun = ++run;
    opener = from || document.activeElement;
    const drawer = drawerEl();
    drawer.replaceChildren(header("Incident details"), el("div", { class: "drawer-body" }, [el("div", { class: "skel", vars: { "--h": "320px" } })]));
    drawer.hidden = false;
    scrimEl().hidden = false;
    scrimEl().onclick = closeDrawer;
    document.addEventListener("keydown", onKey);
    drawer.querySelector("button").focus();
    try {
        const item = await data.incident(severity, timestamp);
        if (myRun !== run) return;
        drawer.replaceChildren(...render(item));
        drawer.querySelector("button").focus();
    } catch (err) {
        if (myRun !== run) return;
        drawer.replaceChildren(header("Incident details"), el("div", { class: "drawer-body" }, [
            el("div", { class: "error-box" }, [
                el("p", { text: "Could not load this incident. " + err.message }),
                el("button", { class: "btn", type: "button", text: "Retry", onclick: () => openIncident(severity, timestamp, opener) })
            ])
        ]));
    }
}
