// Search palette (Ctrl/Cmd+K, or /): jump to a page, an IP address, an IAM user or a technique by typing.
// Addresses and users come from the latest incidents (the same shared sample the Analytics cards use), so the list
// is whatever shows up in the data; it needs no endpoint of its own. Anything typed can also be sent to the Incidents filters.

import * as data from "./data.js";
import { el, icon, ICONS, userShort, fmtNum, plural, sevOfScore } from "./dom.js";
import { TECHNIQUES } from "./mitre.js";
import { entityHref } from "./links.js";
import { closeFocus, isFocused } from "./focus.js";

const MAX_PER_GROUP = 6;
let cfg = { pages: [], actions: [] };
let built = null;
let open = false;
let opener = null;
let query = "";
let active = 0;
let flat = [];
let index = { state: "idle", ips: [], users: [] };
let loadRun = 0;

const layer = () => document.getElementById("palette");
const shell = () => document.getElementById("shell");
const isMac = /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent || "");
export const shortcutLabel = () => (isMac ? "⌘K" : "Ctrl K");

function build() {
    const input = el("input", {
        type: "text", id: "pal-input", role: "combobox", autocomplete: "off", spellcheck: "false", maxlength: "64",
        "aria-expanded": "true", "aria-controls": "pal-list", "aria-autocomplete": "list", "aria-label": "Search", placeholder: "Search IPs, users, techniques"
    });
    const list = el("ul", { id: "pal-list", class: "pal-list", role: "listbox", "aria-label": "Results" });
    const box = el("div", { class: "pal-box", role: "dialog", "aria-modal": "true", "aria-label": "Search" }, [
        el("div", { class: "pal-input" }, [icon(ICONS.search), input, el("kbd", { text: "Esc" })]),
        list,
        el("footer", { class: "pal-foot" }, [el("span", { text: "↑ ↓ move" }), el("span", { text: "Enter open" }), el("span", { text: "Esc close" })])
    ]);
    layer().replaceChildren(box);
    layer().addEventListener("mousedown", (e) => { if (e.target === layer()) close(); });
    input.addEventListener("input", () => { query = input.value; active = 0; render(); });
    input.addEventListener("keydown", onInputKey);
    return { input, list };
}

function onInputKey(e) {
    if (e.key === "Escape") { e.preventDefault(); close(); return; }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        if (!flat.length) return;
        active = (active + (e.key === "ArrowDown" ? 1 : -1) + flat.length) % flat.length;
        paintActive(true);
        return;
    }
    if (e.key === "Enter") {
        e.preventDefault();
        if (flat[active]) choose(flat[active]);
        return;
    }
    // Keep Tab from leaving the dialog: the field is the only thing to reach
    if (e.key === "Tab") e.preventDefault();
}

// ---------- Matching ----------

const norm = (s) => String(s || "").toLowerCase();

function rank(rows, text) {
    const q = norm(query).trim();
    if (!q) return rows.slice(0, MAX_PER_GROUP);
    return rows
        .map((row) => ({ row, at: norm(text(row)).indexOf(q) }))
        .filter((r) => r.at !== -1)
        .sort((a, b) => (a.at === 0 ? 0 : 1) - (b.at === 0 ? 0 : 1) || (b.row.count || 0) - (a.row.count || 0))
        .map((r) => r.row)
        .slice(0, MAX_PER_GROUP);
}

function groups() {
    const q = query.trim();
    const out = [];
    const pages = rank(cfg.pages, (p) => p.label).map((p) => ({ label: p.label, sub: "Page", icon: p.icon, run: () => { window.location.hash = p.hash; } }));
    if (pages.length) out.push({ title: "Pages", rows: pages });

    const ips = rank(index.ips, (r) => r.name).map((r) => ({
        label: r.name, mono: true, sub: plural(r.count, "incident") + " · highest score " + fmtNum(r.maxScore) + " · " + sevOfScore(r.maxScore).toLowerCase(), icon: ICONS.incidents,
        run: () => { window.location.hash = entityHref("ip", r.name); }
    }));
    if (ips.length) out.push({ title: "IP addresses", rows: ips });

    const users = rank(index.users, (r) => r.name).map((r) => ({
        label: r.name, sub: plural(r.count, "incident") + " · highest score " + fmtNum(r.maxScore) + " · " + sevOfScore(r.maxScore).toLowerCase(), icon: ICONS.incidents,
        run: () => { window.location.hash = entityHref("user", r.name); }
    }));
    if (users.length) out.push({ title: "IAM users", rows: users });

    const techs = rank(Object.values(TECHNIQUES), (t) => t.id + " " + t.name + " " + t.tactic).map((t) => ({
        label: t.id, mono: true, sub: t.name + " · " + t.tactic, icon: ICONS.shieldCheck,
        run: () => import("./mitrecard.js").then((m) => m.openTechnique(t.id, opener))
    }));
    if (techs.length) out.push({ title: "MITRE ATT&CK techniques", rows: techs });

    const acts = rank(cfg.actions, (a) => a.label).map((a) => ({ label: a.label, sub: "Action", icon: a.icon, run: a.run }));
    if (acts.length) out.push({ title: "Actions", rows: acts });

    // What was typed can also go straight to the filters of the Incidents page
    if (q) {
        const rows = [];
        if (/^[0-9a-f:.]{2,45}$/i.test(q)) rows.push({ label: "Incidents from addresses starting with " + q, sub: "Filter on Incidents", icon: ICONS.filter, run: () => { window.location.hash = "#/incidents?ip=" + encodeURIComponent(q); } });
        rows.push({ label: "Incidents of IAM users containing \"" + q + "\"", sub: "Filter on Incidents", icon: ICONS.filter, run: () => { window.location.hash = "#/incidents?user=" + encodeURIComponent(q); } });
        out.push({ title: "Search in incidents", rows });
    }
    return out;
}

// ---------- Drawing ----------

function render() {
    const { list } = built;
    const gs = groups();
    flat = [];
    const nodes = [];
    gs.forEach((g) => {
        nodes.push(el("li", { class: "pal-group", role: "presentation", text: g.title }));
        g.rows.forEach((row) => {
            const n = flat.length;
            flat.push(row);
            const node = el("li", { class: "pal-item", role: "option", id: "pal-o-" + n, "aria-selected": "false" }, [
                el("span", { class: "pal-ic" }, [row.icon ? icon(row.icon) : null]),
                el("span", { class: "pal-text" }, [el("b", { class: row.mono ? "mono" : "", text: row.label }), el("small", { text: row.sub })]),
                el("kbd", { class: "pal-go", text: "↵" })
            ]);
            node.addEventListener("mousemove", () => { if (active !== n) { active = n; paintActive(false); } });
            node.addEventListener("click", () => choose(row));
            nodes.push(node);
        });
    });
    if (index.state === "loading") nodes.push(el("li", { class: "pal-note", role: "presentation", text: "Loading addresses and users..." }));
    if (index.state === "error") nodes.push(el("li", { class: "pal-note", role: "presentation", text: "Could not load addresses and users. Pages and techniques still work." }));
    if (!flat.length && index.state !== "loading") nodes.unshift(el("li", { class: "pal-note", role: "presentation", text: "Nothing matches \"" + query.trim() + "\"." }));
    list.replaceChildren(...nodes);
    active = Math.min(active, Math.max(0, flat.length - 1));
    paintActive(false);
}

function paintActive(scroll) {
    const { input, list } = built;
    list.querySelectorAll(".pal-item").forEach((node, n) => {
        const on = n === active;
        node.classList.toggle("on", on);
        node.setAttribute("aria-selected", String(on));
        if (on) {
            input.setAttribute("aria-activedescendant", node.id);
            if (scroll) node.scrollIntoView({ block: "nearest" });
        }
    });
}

function choose(row) {
    close(false);
    row.run();
}

// ---------- Open and close ----------

async function loadIndex() {
    const mine = ++loadRun;
    index.state = "loading";
    try {
        const res = await data.sample(0);
        if (mine !== loadRun) return;
        const ips = new Map();
        const users = new Map();
        const add = (map, name, score) => {
            if (!name) return;
            const row = map.get(name) || { name, count: 0, maxScore: 0 };
            row.count++;
            row.maxScore = Math.max(row.maxScore, score);
            map.set(name, row);
        };
        res.items.forEach((i) => {
            const score = Number(i.globalScore) || 0;
            add(ips, i.sourceIPAddress, score);
            add(users, userShort(i.userIdentity), score);
        });
        const byCount = (a, b) => b.count - a.count || b.maxScore - a.maxScore;
        index = { state: "ready", ips: [...ips.values()].sort(byCount), users: [...users.values()].sort(byCount) };
    } catch (e) {
        if (mine !== loadRun) return;
        index = { state: "error", ips: [], users: [] };
    }
    if (open) render();
}

export function openSearch() {
    if (open || shell().hidden) return;
    if (!document.getElementById("modal").hidden) return; // a technique card is open: it keeps the keyboard
    if (isFocused()) closeFocus(true);
    if (!built) built = build();
    opener = document.activeElement;
    open = true;
    query = "";
    active = 0;
    built.input.value = "";
    layer().hidden = false;
    shell().inert = true;
    document.documentElement.classList.add("palette-open");
    window.addEventListener("hashchange", onHash);
    render();
    built.input.focus();
    loadIndex();
}

function onHash() { close(false); }

export function close(restoreFocus = true) {
    if (!open) return;
    open = false;
    loadRun++;
    layer().hidden = true;
    shell().inert = false;
    document.documentElement.classList.remove("palette-open");
    window.removeEventListener("hashchange", onHash);
    if (restoreFocus && opener && document.contains(opener)) opener.focus({ preventScroll: true });
}

const typing = (t) => t && (t.isContentEditable || /^(input|textarea|select)$/i.test(t.tagName));

// pages: [{label, hash, icon}], actions: [{label, icon, run}]
export function initSearch(options) {
    cfg = options;
    document.addEventListener("keydown", (e) => {
        if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "k") {
            e.preventDefault();
            if (open) close(); else openSearch();
            return;
        }
        if (e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey && !typing(e.target) && !open) {
            e.preventDefault();
            openSearch();
        }
    });
    const button = document.getElementById("search-btn");
    if (button) {
        button.replaceChildren(icon(ICONS.search), el("span", { class: "search-text", text: "Search" }), el("kbd", { text: shortcutLabel() }));
        button.addEventListener("click", openSearch);
    }
}
