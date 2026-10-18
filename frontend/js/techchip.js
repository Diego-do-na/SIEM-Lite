// A technique id as a button: it opens the ATT&CK card. Inside a table row it must not also open the incident.
// Lives apart from views/ui.js so that charts and the explanations of the expanded cards can use it too.

import { el, techName } from "./dom.js";

export function techChip(id, { showName = false } = {}) {
    const name = techName(id);
    const button = el("button", {
        class: "chip tech-btn", type: "button", "aria-haspopup": "dialog",
        title: (name ? name + ". " : "") + "Open the technique card",
        onclick: (e) => { e.stopPropagation(); import("./mitrecard.js").then((m) => m.openTechnique(id, button)); },
        onkeydown: (e) => e.stopPropagation()
    }, [id, showName && name ? el("span", { class: "chip-name", text: name }) : null]);
    return button;
}
