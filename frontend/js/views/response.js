// Response: what SIEM Lite fixes on its own, what it only reports, and what could be automated next.
// The first part is real: it comes from the same tables the detection and the response Lambda use (js/mitre.js)
// and from the incidents themselves. The last two cards are previews of ideas, labeled as such on screen.

import * as data from "../data.js";
import { isMock } from "../api.js";
import { el, icon, ICONS, fmtNum, fmtPct, sevClass, techName } from "../dom.js";
import { ratioBars } from "../charts.js";
import * as stats from "../stats.js";
import { ACTIONS, TECHNIQUES } from "../mitre.js";
import { techChip } from "../techchip.js";
import * as ex from "../explain.js";
import { panel, pageHead, statCard } from "./ui.js";

const sevLabel = (s) => s.charAt(0) + s.slice(1).toLowerCase();
const AUTOMATIC = Object.entries(ACTIONS).filter(([, a]) => a.soar);
const ALERT_ONLY = Object.entries(ACTIONS).filter(([, a]) => !a.soar);

// Ideas for the actions that only raise an alert today. None of them runs; they say what each one would need
const IDEAS = {
    UpdateTrail: ["Restore the previous trail settings", "The settings before the change, from AWS Config history"],
    DeleteSecurityGroup: ["Recreate the group with its rules", "The group's previous configuration, from AWS Config history"],
    AuthorizeSecurityGroupIngress: ["Remove the rule that was added", "The exact rule, which the CloudTrail event already carries"],
    AuthorizeSecurityGroupEgress: ["Remove the rule that was added", "The exact rule, which the CloudTrail event already carries"],
    RevokeSecurityGroupIngress: ["Add the removed rule back", "The removed rule, from the event or from AWS Config history"],
    RevokeSecurityGroupEgress: ["Add the removed rule back", "The removed rule, from the event or from AWS Config history"],
    CreateSecurityGroup: ["Delete it when nothing uses it", "A check that no resource is attached to the group"]
};

function playbooks() {
    return el("div", { class: "play-grid" }, AUTOMATIC.map(([name, a], index) => el("article", { class: "play", vars: { "--i": String(index) } }, [
        el("header", {}, [el("span", { class: "pill soar", text: "Automatic" }), techChip(a.technique)]),
        el("h3", { class: "mono", text: name }),
        el("dl", {}, [
            el("div", {}, [el("dt", { text: "When it sees" }), el("dd", { text: a.what })]),
            el("div", {}, [el("dt", { text: "It does" }), el("dd", { text: a.soar })]),
            el("div", {}, [el("dt", { text: "Weight" }), el("dd", { class: "mono", text: a.weight + " points" })])
        ])
    ])));
}

function leftToYou() {
    return el("div", { class: "table-wrap" }, [el("table", { class: "table idea-table" }, [
        el("thead", {}, [el("tr", {}, ["Action it reports", "What happened", "A response that could be built", "What it would need"].map((h, i) => el("th", { scope: "col", class: i > 1 ? "hide-sm" : "", text: h })))]),
        el("tbody", {}, ALERT_ONLY.map(([name, a]) => {
            const idea = IDEAS[name];
            return el("tr", {}, [
                el("td", {}, [el("b", { class: "mono", text: name })]),
                el("td", { text: a.what }),
                el("td", { class: "hide-sm" }, idea ? idea[0] : "–"),
                el("td", { class: "hide-sm muted", text: idea ? idea[1] : "" })
            ]);
        }))
    ])]);
}

// Resources that would carry the recovery tag. Example rows exist only in the demo; real data has nothing to show yet
const EXAMPLE = [
    ["management-events", "CloudTrail trail", "3 hours ago", "Protected"],
    ["alias/app-data", "KMS key", "3 hours ago", "Protected"],
    ["sg-web-public", "Security group", "yesterday", "Protected"],
    ["alias/backups", "KMS key", "yesterday", "Protected"]
];

function protectedResources() {
    const steps = [
        ["1", "Tag it", "A resource is marked with the recovery tag. Nothing else changes for the people who use it."],
        ["2", "SIEM Lite saves its configuration", "The settings of every tagged resource are stored, and refreshed when they change on purpose."],
        ["3", "It can be put back", "If the resource is deleted or altered, the response rebuilds it from the saved configuration."]
    ];
    const flow = el("ol", { class: "flow" }, steps.map(([n, title, text]) => el("li", {}, [el("span", { class: "flow-n", text: n }), el("div", {}, [el("b", { text: title }), el("p", { text })])])));
    const table = isMock()
        ? el("div", { class: "table-wrap" }, [el("table", { class: "table idea-table" }, [
            el("thead", {}, [el("tr", {}, ["Resource", "Type", "Configuration saved", "Status"].map((h) => el("th", { scope: "col", text: h })))]),
            el("tbody", {}, EXAMPLE.map((row) => el("tr", {}, row.map((cell, i) => el("td", { class: i === 0 ? "mono" : "", text: cell })))))
        ]), el("p", { class: "panel-foot", text: "Example data, to show the layout. These resources do not exist." })])
        : el("p", { class: "empty", text: "No protected resources to show yet. This card is fed by the recovery feature planned for the next version." });
    return el("div", { class: "protect" }, [flow, table]);
}

export function mount(root, ctx) {
    const strip = el("section", { class: "grid-stats-4", "aria-label": "Response figures" });
    const severityCard = panel({ title: "Mitigated, by severity", sub: "Share of incidents where an automatic response ran", minHeight: 200 });
    const techniqueCard = panel({ title: "Mitigated, by technique", sub: "Only logging and key actions have a response today", minHeight: 200 });
    const playCard = panel({ title: "What it does on its own", sub: "The actions the response Lambda answers, and how", expandable: false });
    playCard.show(playbooks());
    const leftCard = panel({ title: "What it leaves to you", sub: "Detected and reported, but nothing is changed automatically today", expandable: false });
    leftCard.show(leftToYou());
    leftCard.note("The last two columns are ideas for later versions. None of them runs today. Undoing a change automatically can overwrite something legitimate, so each one should be opt-in; see the card below.");
    const protectCard = panel({
        title: "Protected resources", sub: "Idea: tag a resource with recovery and SIEM Lite saves and can rebuild it", expandable: false,
        action: el("span", { class: "pill planned", title: "Not built yet. It needs backend work in the next version.", text: "Preview" })
    });
    protectCard.show(protectedResources());

    root.append(
        pageHead("Response", "What SIEM Lite fixes on its own, what it only reports, and what could be automated next"),
        strip,
        el("div", { class: "grid-2" }, [severityCard.root, techniqueCard.root]),
        el("div", { class: "grid-1" }, [playCard.root]),
        el("div", { class: "grid-1" }, [leftCard.root]),
        el("div", { class: "grid-1" }, [protectCard.root])
    );

    function stripSkeleton() {
        strip.replaceChildren(...Array.from({ length: 4 }, () => el("div", { class: "card kpi" }, [el("div", { class: "skel", vars: { "--h": "74px" } })])));
    }

    let run = 0;
    async function refresh(soft = false) {
        const mine = ++run;
        const days = ctx.days();
        if (!soft) stripSkeleton();
        const sampled = () => data.sample(days);
        const stale = () => mine !== run;

        sampled().then((res) => {
            if (stale()) return;
            const s = stats.summary(res.items);
            const open = res.items.filter((i) => !i.responseTaken && (i.severity === "CRITICAL" || i.severity === "HIGH")).length;
            strip.replaceChildren(
                statCard("Mitigated automatically", fmtPct(s.mitigationRate), s.total ? fmtNum(s.mitigated) + " of " + fmtNum(s.total) + " incidents" : "No incidents in this range"),
                statCard("High and Critical left to you", fmtNum(open), "No automatic response ran for them"),
                statCard("Automatic responses", String(AUTOMATIC.length), "Actions the response Lambda answers"),
                statCard("Alert-only actions", String(ALERT_ONLY.length), "Plus denied calls with no rule of their own")
            );
        }).catch((err) => {
            if (stale() || soft) return;
            strip.replaceChildren(el("div", { class: "card panel span-all" }, [el("div", { class: "error-box" }, [
                el("p", { text: "Could not load the figures. " + err.message }),
                el("button", { class: "btn", type: "button", text: "Retry", onclick: () => refresh() })
            ])]));
        });

        const from = (card, build) => card.load(sampled, (res) => {
            if (!res.items.length) { card.empty("No incidents in this range"); return; }
            build(res);
            card.note(res.truncated ? "Based on the latest " + fmtNum(res.items.length) + " incidents of this range; there are more, so figures are an estimate." : "Based on all " + fmtNum(res.items.length) + " incidents of this range.");
        }, { soft });

        await Promise.all([
            from(severityCard, (res) => {
                const by = stats.mitigationBySeverity(res.items);
                severityCard.show(ratioBars(by.map((r) => ({ label: sevLabel(r.sev), color: "var(--sev-" + sevClass(r.sev) + ")", part: r.mitigated, whole: r.total }))));
                severityCard.explain(ex.mitigationExplain(by));
            }),
            from(techniqueCard, (res) => {
                const rows = stats.mitigationByTechnique(res.items, Object.keys(TECHNIQUES));
                techniqueCard.show(ratioBars(rows.map((r, i) => ({ label: r.technique + " " + techName(r.technique), color: "var(--cat-" + ((i % 8) + 1) + ")", part: r.mitigated, whole: r.total }))));
                techniqueCard.explain(ex.responseTechniqueExplain(rows));
            })
        ]);
    }

    refresh();
    return { refresh, destroy() { run++; } };
}
