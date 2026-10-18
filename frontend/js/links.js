// Links to the page of an entity: an IP address or an IAM user (#/entity/ip/<ip>, #/entity/user/<name>).
// Inside a table row the link must not also open the incident of that row, so clicks stop there.

import { el } from "./dom.js";

export const entityHref = (kind, value) => "#/entity/" + kind + "/" + encodeURIComponent(value);

export function entityLink(kind, value, { mono = kind === "ip" } = {}) {
    return el("a", {
        class: "entity-link" + (mono ? " mono" : ""), href: entityHref(kind, value), title: "Open the page of this " + (kind === "ip" ? "address" : "user"),
        onclick: (e) => e.stopPropagation(), onkeydown: (e) => e.stopPropagation(), text: value
    });
}

// "ip/203.0.113.42" or "user/svc-deploy" (the part of the hash after #/entity/). null when it is not a valid entity
export function parseEntity(param) {
    const [kind, ...rest] = String(param || "").split("/");
    if (kind !== "ip" && kind !== "user") return null;
    let value = "";
    try { value = decodeURIComponent(rest.join("/")); } catch (e) { return null; }
    // eslint-disable-next-line no-control-regex
    if (!value || value.length > 64 || /[\u0000-\u001f]/.test(value)) return null;
    return { kind, value };
}
