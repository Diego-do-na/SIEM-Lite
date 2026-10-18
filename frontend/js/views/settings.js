// Settings: layout prepared for system health and admin actions. Not connected to anything yet:
// /health only answers "ok" today and admin actions need POST /actions (planned for 1.1).

import { el } from "../dom.js";
import { pageHead } from "./ui.js";

function healthCard(name, text) {
    return el("section", { class: "card panel health-card" }, [
        el("span", { class: "name", text: name }),
        el("span", { class: "pill", text: "Not connected" }),
        el("p", { class: "sub", text })
    ]);
}

export function mount(root) {
    const actions = el("section", { class: "card panel" }, [
        el("header", { class: "panel-head" }, [el("div", {}, [el("h2", { text: "Admin actions" }), el("p", { class: "sub", text: "Available to the admin group once POST /actions exists" })])]),
        el("div", { class: "actions-row" }, [
            el("button", { class: "btn", type: "button", disabled: true, text: "Acknowledge incident" }),
            el("button", { class: "btn", type: "button", disabled: true, text: "Close incident" }),
            el("button", { class: "btn", type: "button", disabled: true, text: "Re-run automated response" })
        ])
    ]);
    root.append(
        pageHead("Settings", "System health and administration"),
        el("div", { class: "note" }, [el("span", { text: "Preview only. Nothing here is connected to data or actions yet." })]),
        el("div", { class: "grid-3" }, [
            healthCard("API", "Request rate, errors and latency"),
            healthCard("Detection pipeline", "Lambda errors and stream lag"),
            healthCard("Analytics", "Athena queries and last export")
        ]),
        actions
    );
    return { refresh() {}, destroy() {} };
}
