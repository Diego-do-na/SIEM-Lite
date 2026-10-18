// App shell: sign-in, navigation, theme, polling for new incidents. Views live in js/views.

import * as auth from "./auth.js";
import { api, enableMock, isMock, setSignedOutHandler } from "./api.js";
import * as data from "./data.js";
import { openIncident, closeDrawer } from "./drawer.js";
import { $, el, icon, ICONS, brandMark, clock } from "./dom.js";

const ROUTES = [
    { id: "overview", label: "Overview", title: "Security overview", icon: ICONS.overview, range: true, load: () => import("./views/overview.js") },
    { id: "incidents", label: "Incidents", title: "Incidents", icon: ICONS.incidents, range: false, load: () => import("./views/incidents.js") },
    { id: "analytics", label: "Analytics", title: "Analytics", icon: ICONS.analytics, range: true, load: () => import("./views/analytics.js") },
    { id: "reports", label: "Reports", title: "Reports", icon: ICONS.reports, range: false, soon: true, load: () => import("./views/reports.js") },
    { id: "settings", label: "Settings", title: "Settings", icon: ICONS.settings, range: false, soon: true, load: () => import("./views/settings.js") }
];

const app = { days: 30, view: null, route: null, pollTimer: null, started: false };

// Per-viewer conveniences only. Storage can be blocked, so every access is guarded
const store = {
    get(key) { try { return localStorage.getItem(key); } catch (e) { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch (e) { /* ignore */ } }
};

function showBanner(message) {
    const b = $("#banner");
    b.textContent = message || "";
    b.hidden = !message;
    const lb = $("#login-banner");
    lb.textContent = message || "";
    lb.hidden = !message;
}

// ---------- Theme ----------

function currentTheme() {
    const saved = document.documentElement.getAttribute("data-theme");
    if (saved) return saved;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    $("#theme").replaceChildren(icon(theme === "dark" ? ICONS.sun : ICONS.moon));
}

// ---------- Routing ----------

function routeFromHash() {
    const id = window.location.hash.replace(/^#\/?/, "").split(/[/?]/)[0];
    return ROUTES.find((r) => r.id === id) || ROUTES[0];
}

function renderNav(active) {
    $("#nav").replaceChildren(...ROUTES.map((r) => el("a", {
        class: "nav-item", href: "#/" + r.id, "aria-current": r.id === active.id ? "page" : null
    }, [icon(r.icon), el("span", { class: "nav-label", text: r.label }), r.soon ? el("span", { class: "nav-tag", text: "Soon" }) : null])));
}

const ctx = {
    days: () => app.days,
    openIncident: (severity, timestamp) => openIncident(severity, timestamp, document.activeElement)
};

async function showRoute(firstLoad) {
    const route = routeFromHash();
    if (app.view) app.view.destroy();
    closeDrawer();
    app.route = route;
    renderNav(route);
    $("#crumb").textContent = route.label;
    $("#range").hidden = !route.range;
    document.title = route.label + " · SIEM Lite";
    const view = $("#view");
    view.replaceChildren();
    const module = await route.load();
    if (app.route !== route) return; // the user already moved on
    app.view = module.mount(view, ctx);
    if (!firstLoad) view.focus({ preventScroll: true });
}

function markUpdated() {
    $("#updated").textContent = "Last updated " + clock(Date.now() / 1000) + " UTC";
}

// ---------- Polling ----------

async function poll() {
    try {
        const stats = await data.stats();
        if (stats.lastIncidentAt !== data.version.current) {
            const first = data.version.current === null;
            data.version.current = stats.lastIncidentAt;
            if (!first && app.view) app.view.refresh();
        }
        markUpdated();
        showBanner("");
    } catch (err) {
        if (err.status !== 401) showBanner(err.message);
    }
}

// ---------- Flow ----------

function showLogin() {
    if (app.pollTimer) clearInterval(app.pollTimer);
    app.started = false;
    $("#shell").hidden = true;
    $("#login").hidden = false;
}

async function start() {
    $("#login").hidden = true;
    $("#shell").hidden = false;
    app.started = true;

    const who = isMock() ? { name: "demo", groups: ["admin"] } : auth.claims();
    $("#username").textContent = who.name;
    $("#avatar").textContent = who.name.slice(0, 2).toUpperCase();
    const role = who.groups.includes("admin") ? "admin" : who.groups.includes("viewer") ? "viewer" : "";
    $("#role").textContent = role;
    $("#role").hidden = !role;
    $("#logout").hidden = isMock();

    // The version has to be known before the first view asks for data
    await poll();
    await showRoute(true);
    app.pollTimer = setInterval(poll, ((window.SIEM_CONFIG && window.SIEM_CONFIG.pollSeconds) || 10) * 1000);
}

function bind() {
    $("#brand-mark").replaceChildren(brandMark());
    $("#login-mark").replaceChildren(brandMark());
    $("#refresh").replaceChildren(icon(ICONS.refresh));
    $("#collapse-icon").replaceChildren(icon(ICONS.chevronsLeft));
    applyTheme(store.get("theme") || currentTheme());

    $("#theme").addEventListener("click", () => {
        const next = currentTheme() === "dark" ? "light" : "dark";
        applyTheme(next);
        store.set("theme", next);
    });
    $("#collapse").addEventListener("click", () => {
        const shell = $("#shell");
        shell.classList.toggle("collapsed");
        store.set("collapsed", shell.classList.contains("collapsed") ? "1" : "0");
    });
    if (store.get("collapsed") === "1") $("#shell").classList.add("collapsed");

    $("#range").addEventListener("click", (e) => {
        const btn = e.target.closest("button");
        if (!btn) return;
        app.days = Number(btn.dataset.days);
        document.querySelectorAll("#range button").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
        if (app.view) app.view.refresh();
    });
    $("#refresh").addEventListener("click", () => {
        data.clearMemo();
        poll();
        if (app.view) app.view.refresh();
    });
    $("#login-btn").addEventListener("click", auth.login);
    $("#logout").addEventListener("click", auth.logout);
    window.addEventListener("hashchange", () => { if (app.started) showRoute(false); });
}

async function main() {
    bind();
    setSignedOutHandler(showLogin);

    // ?mock=1 shows the dashboard with generated data (also ?mock=empty and ?mock=error)
    const mock = new URLSearchParams(window.location.search).get("mock");
    if (mock) {
        await enableMock(mock);
        start();
        return;
    }
    if (!auth.configured()) {
        showLogin();
        $("#login-btn").disabled = true;
        showBanner("Missing config.js: copy config.example.js and fill it with the Terraform outputs, or open the page with ?mock=1 for demo data.");
        return;
    }
    try {
        await auth.handleRedirect();
    } catch (err) {
        showBanner(err.message);
    }
    if (await auth.getToken()) start();
    else showLogin();
}

main();
