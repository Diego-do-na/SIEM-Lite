// The ATT&CK card: opens over any page when a technique id is selected.
// Closes with Esc, the scrim, the close button or any navigation, and gives focus back to what opened it.

import * as data from "./data.js";
import { el, icon, ICONS, fmtNum } from "./dom.js";
import { TECHNIQUES, ACTIONS, MITRE_NOTICE } from "./mitre.js";

let opener = null;
let run = 0;

const modal = () => document.getElementById("modal");
const scrim = () => document.getElementById("scrim");

export function closeTechnique() {
    run++;
    modal().hidden = true;
    scrim().hidden = true;
    document.removeEventListener("keydown", onKey);
    window.removeEventListener("hashchange", closeTechnique);
    if (opener && document.contains(opener)) opener.focus();
    opener = null;
}

function onKey(e) {
    if (e.key === "Escape") closeTechnique();
}

function section(title, children) {
    return el("section", { class: "m-sec" }, [el("h3", { text: title }), ...[].concat(children)]);
}

function render(id) {
    const t = TECHNIQUES[id];
    if (!t) {
        return [
            el("header", { class: "m-head" }, [el("span", { class: "chip", text: id }), closeButton()]),
            el("div", { class: "m-body" }, [
                el("h2", { id: "modal-title", text: "Technique not in the dictionary" }),
                el("p", { class: "muted", text: "SIEM Lite does not emit this technique yet. You can read about it on the MITRE ATT&CK site." }),
                el("a", { class: "btn", href: "https://attack.mitre.org/techniques/" + encodeURIComponent(id).replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", text: "Open on attack.mitre.org" })
            ])
        ];
    }
    const count = el("span", { class: "m-count", text: "Counting incidents..." });
    const events = t.events.map((name) => {
        const a = ACTIONS[name];
        return a ? el("li", {}, [el("code", { text: name }), el("span", { class: "m-weight", text: a.weight + " pts" })]) : el("li", {}, [el("span", { text: name })]);
    });
    const bullets = (list) => el("ul", { class: "m-list" }, list.map((m) => el("li", { text: m })));
    return [
        el("header", { class: "m-head" }, [
            el("div", { class: "m-ids" }, [el("span", { class: "chip", text: t.id }), el("span", { class: "m-tactic", text: t.tactic })]),
            closeButton()
        ]),
        el("div", { class: "m-body" }, [
            el("div", {}, [
                el("h2", { id: "modal-title", text: t.name }),
                t.parent ? el("p", { class: "muted", text: "Sub-technique of " + t.parent }) : null
            ]),
            el("div", { class: "m-about" }, t.about.map((p) => el("p", { text: p }))),
            el("div", { class: "m-stat" }, [count]),
            section("In AWS", [el("p", { text: t.inAws }), el("ul", { class: "m-events" }, events)]),
            section("Seen in the real world", [el("ul", { class: "m-examples" }, t.examples.map((x) => el("li", {}, [el("b", { text: x.name }), el("span", { text: x.text })])))]),
            section("How SIEM Lite detects it", [el("p", { text: t.detection })]),
            section("Automated response", [el("p", { text: t.response })]),
            section("What to check when you see it", [bullets(t.investigate)]),
            section("Normal activity that can look the same", [bullets(t.benign)]),
            section("How to reduce the risk", [el("ul", { class: "m-list" }, t.mitigations.map((m) => el("li", {}, [
                m.id ? el("span", { class: "m-ref", title: m.name, text: m.id }) : null, m.name ? el("b", { text: m.name + ". " }) : null, m.text
            ])))]),
            el("footer", { class: "m-foot" }, [
                el("a", { class: "btn btn-primary", href: "#/incidents?technique=" + encodeURIComponent(t.id), text: "View incidents" }),
                el("a", { class: "btn", href: t.url, target: "_blank", rel: "noopener noreferrer", text: "Open on attack.mitre.org" })
            ]),
            el("p", { class: "m-notice", text: MITRE_NOTICE })
        ])
    ];
}

const closeButton = () => el("button", { class: "icon-btn", type: "button", "aria-label": "Close", onclick: closeTechnique }, [icon(ICONS.close)]);

export async function openTechnique(id, from) {
    const mine = ++run;
    opener = from || document.activeElement;
    const box = modal();
    const nodes = render(id);
    box.replaceChildren(...nodes);
    box.hidden = false;
    scrim().hidden = false;
    scrim().onclick = closeTechnique;
    document.addEventListener("keydown", onKey);
    window.addEventListener("hashchange", closeTechnique);
    box.querySelector("button").focus();

    // How many incidents carry it in the last 30 days. The card is useful without this number, so a failure is silent
    const target = box.querySelector(".m-count");
    if (!target) return;
    try {
        const res = await data.mitre(30);
        if (mine !== run) return;
        const row = res.data.find((r) => r.technique === id);
        const n = row ? Number(row.incidents) : 0;
        target.textContent = n ? fmtNum(n) + " " + (n === 1 ? "incident" : "incidents") + " in the last 30 days" : "No incidents with this technique in the last 30 days";
        target.classList.toggle("hot", n > 0);
    } catch (e) {
        if (mine === run) target.textContent = "";
    }
}

