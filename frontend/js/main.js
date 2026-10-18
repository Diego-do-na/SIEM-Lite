// App shell: sign-in, navigation, theme, and the automatic refresh. Views live in js/views.

import * as auth from "./auth.js";
import { enableMock, isMock, setSignedOutHandler } from "./api.js";
import * as data from "./data.js";
import { openIncident, closeDrawer } from "./drawer.js";
import { $, el, icon, ICONS, brandMark, clock, plural, reducedMotion } from "./dom.js";

const ROUTES = [
    { id: "overview", label: "Overview", icon: ICONS.overview, range: true, load: () => import("./views/overview.js") },
    { id: "incidents", label: "Incidents", icon: ICONS.incidents, range: false, load: () => import("./views/incidents.js") },
    { id: "analytics", label: "Analytics", icon: ICONS.analytics, range: true, load: () => import("./views/analytics.js") },
    { id: "reports", label: "Reports", icon: ICONS.reports, range: false, soon: true, load: () => import("./views/reports.js") },
    { id: "settings", label: "Settings", icon: ICONS.settings, range: false, soon: true, load: () => import("./views/settings.js") }
];

const app = {
    days: 30, view: null, route: null, nav: 0,
    pollTimer: null, clockTimer: null, polling: false, started: false,
    lastOk: null, online: true, total: null, toastTimer: null
};

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

function applyTheme(theme, animate) {
    const root = document.documentElement;
    // Colors fade only while switching, so nothing else pays for a transition
    if (animate && !reducedMotion()) {
        root.classList.add("theming");
        setTimeout(() => root.classList.remove("theming"), 400);
    }
    root.setAttribute("data-theme", theme);
    const glyph = icon(theme === "dark" ? ICONS.sun : ICONS.moon);
    if (animate) glyph.classList.add("turn");
    $("#theme").replaceChildren(glyph);
}

// ---------- Sidebar ----------

function setCollapsed(on) {
    $("#shell").classList.toggle("collapsed", on);
    const button = $("#collapse");
    const label = on ? "Expand sidebar" : "Collapse sidebar";
    button.setAttribute("aria-expanded", String(!on));
    button.setAttribute("aria-label", label);
    button.title = label;
    store.set("collapsed", on ? "1" : "0");
}

// ---------- Routing ----------

function routeFromHash() {
    const [id, param] = window.location.hash.replace(/^#\/?/, "").split("?")[0].split("/");
    return { route: ROUTES.find((r) => r.id === id) || ROUTES[0], param: param || "" };
}

function renderNav(active) {
    $("#nav").replaceChildren(...ROUTES.map((r) => el("a", {
        class: "nav-item", href: "#/" + r.id, title: r.label, "aria-current": r.id === active.id ? "page" : null
    }, [icon(r.icon), el("span", { class: "nav-label", text: r.label }), r.soon ? el("span", { class: "nav-tag", text: "Soon" }) : null])));
}

const ctx = {
    days: () => app.days,
    openIncident: (severity, timestamp) => openIncident(severity, timestamp, document.activeElement)
};

async function showRoute(firstLoad) {
    const { route, param } = routeFromHash();
    const token = ++app.nav;
    if (app.view) app.view.destroy();
    app.view = null;
    closeDrawer();
    app.route = route;
    renderNav(route);
    $("#crumb").textContent = route.label;
    $("#range").hidden = !route.range;
    document.title = route.label + " · SIEM Lite";
    const view = $("#view");
    view.replaceChildren();
    const module = await route.load();
    if (token !== app.nav) return; // the user already moved on
    app.view = module.mount(view, Object.assign({ param }, ctx));
    if (!firstLoad) {
        window.scrollTo(0, 0);
        view.focus({ preventScroll: true });
    }
}

// ---------- Automatic refresh ----------
// Every few seconds the cheap /stats call asks for the time of the last incident. Only when it changes
// do the views reload, in place (no skeletons), and a toast says what arrived.

const secondsAgo = (ms) => Math.max(0, Math.round((Date.now() - ms) / 1000));

function renderLive() {
    const live = $("#live");
    if (!app.lastOk) {
        $("#updated").textContent = "Connecting...";
        return;
    }
    const s = secondsAgo(app.lastOk);
    const ago = s < 5 ? "just now" : s < 60 ? s + "s ago" : Math.round(s / 60) + "m ago";
    $("#updated").textContent = (app.online ? "Live · updated " : "Offline · last update ") + ago;
    live.classList.toggle("bad", !app.online);
    live.title = "Last update " + clock(app.lastOk / 1000) + " UTC. Checks for new incidents every "
        + pollSeconds() + " seconds while this tab is open.";
}

const pollSeconds = () => (window.SIEM_CONFIG && window.SIEM_CONFIG.pollSeconds) || 10;

// The refresh icon turns for at least a moment, so a very fast call is still visible
async function spinning(work) {
    const button = $("#refresh");
    button.classList.add("spinning");
    const started = Date.now();
    try {
        return await work();
    } finally {
        setTimeout(() => button.classList.remove("spinning"), Math.max(0, 700 - (Date.now() - started)));
    }
}

function toast(added) {
    const box = $("#toast");
    const onIncidents = app.route && app.route.id === "incidents";
    box.replaceChildren(
        el("i", { class: "live-dot" }),
        el("span", { text: added > 0 ? plural(added, "new incident") + " detected" : "New activity detected" }),
        onIncidents ? null : el("a", { href: "#/incidents", text: "View", onclick: () => { box.hidden = true; } })
    );
    box.hidden = false;
    box.classList.remove("show");
    void box.offsetWidth; // restart the entrance animation
    box.classList.add("show");
    clearTimeout(app.toastTimer);
    app.toastTimer = setTimeout(() => { box.hidden = true; }, 6000);
}

async function poll() {
    if (app.polling) return;
    app.polling = true;
    try {
        await spinning(async () => {
            const stats = await data.stats();
            const all = stats.windows && stats.windows.all ? Number(stats.windows.all.total) : null;
            if (stats.lastIncidentAt !== data.version.current) {
                const first = data.version.current === null;
                data.version.current = stats.lastIncidentAt;
                if (!first) {
                    toast(all !== null && app.total !== null ? all - app.total : 1);
                    if (app.view) app.view.refresh(true);
                }
            }
            app.total = all;
            app.lastOk = Date.now();
            app.online = true;
            showBanner("");
        });
    } catch (err) {
        app.online = false;
        if (err.status !== 401) showBanner(err.message);
    } finally {
        app.polling = false;
        renderLive();
    }
}

// ---------- Flow ----------

function stopTimers() {
    clearInterval(app.pollTimer);
    clearInterval(app.clockTimer);
}

function showLogin() {
    stopTimers();
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
    $("#demo").hidden = !isMock();

    // The version has to be known before the first view asks for data
    await poll();
    await showRoute(true);
    stopTimers();
    app.pollTimer = setInterval(() => { if (!document.hidden) poll(); }, pollSeconds() * 1000);
    app.clockTimer = setInterval(renderLive, 1000);
}

function bind() {
    $("#brand-mark").replaceChildren(brandMark());
    $("#login-mark").replaceChildren(brandMark());
    $("#refresh").replaceChildren(icon(ICONS.refresh));
    $("#collapse").replaceChildren(icon(ICONS.panelLeft));
    applyTheme(store.get("theme") || currentTheme(), false);

    $("#theme").addEventListener("click", () => {
        const next = currentTheme() === "dark" ? "light" : "dark";
        applyTheme(next, true);
        store.set("theme", next);
    });
    $("#collapse").addEventListener("click", () => setCollapsed(!$("#shell").classList.contains("collapsed")));
    setCollapsed(store.get("collapsed") === "1");

    $("#range").addEventListener("click", (e) => {
        const btn = e.target.closest("button");
        if (!btn) return;
        app.days = Number(btn.dataset.days);
        document.querySelectorAll("#range button").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
        if (app.view) app.view.refresh();
    });
    $("#refresh").addEventListener("click", async () => {
        data.clearMemo();
        await poll();
        if (app.view) app.view.refresh();
    });
    // A hidden tab does not poll; coming back catches up at once
    document.addEventListener("visibilitychange", () => { if (!document.hidden && app.started) poll(); });
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
