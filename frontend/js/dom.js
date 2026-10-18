// Small DOM helpers. Everything that comes from the API is written with textContent,
// never as HTML: fields like userIdentity are controlled by whoever generated the event.

const SVG_NS = "http://www.w3.org/2000/svg";

export const $ = (selector, root = document) => root.querySelector(selector);

function append(node, children) {
    (Array.isArray(children) ? children : [children]).forEach((child) => {
        if (child === null || child === undefined || child === false) return;
        node.appendChild(typeof child === "string" || typeof child === "number" ? document.createTextNode(String(child)) : child);
    });
}

// props: text, vars (CSS custom properties), on<event> handlers, anything else is an attribute
export function el(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null || value === false) continue;
        if (key === "text") node.textContent = value;
        else if (key === "vars") Object.entries(value).forEach(([name, v]) => node.style.setProperty(name, v));
        else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
        else node.setAttribute(key, value === true ? "" : value);
    }
    append(node, children);
    return node;
}

export function svg(tag, attrs = {}, children = []) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(attrs)) {
        if (value === undefined || value === null) continue;
        if (key === "text") node.textContent = value;
        else node.setAttribute(key, value);
    }
    append(node, children);
    return node;
}

// 24x24 stroke icons: a list of path data strings
export function icon(paths) {
    return svg("svg", { class: "icon", viewBox: "0 0 24 24", "aria-hidden": "true" },
        paths.map((d) => svg("path", { d })));
}

export const ICONS = {
    overview: ["M3 3h7v9H3z", "M14 3h7v5h-7z", "M14 12h7v9h-7z", "M3 16h7v5H3z"],
    incidents: ["M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z", "M12 8v5", "M12 16.5v.01"],
    analytics: ["M4 20V10", "M10 20V4", "M16 20v-8", "M22 20H2"],
    reports: ["M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z", "M14 3v6h6", "M8 13h8", "M8 17h5"],
    settings: ["M4 7h10", "M18 7h2", "M4 17h2", "M10 17h10", "M14 5v4", "M6 15v4"],
    refresh: ["M21 12a9 9 0 1 1-2.6-6.4", "M21 4v5h-5"],
    sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", "M12 2v2", "M12 20v2", "M4.9 4.9l1.4 1.4", "M17.7 17.7l1.4 1.4", "M2 12h2", "M20 12h2", "M4.9 19.1l1.4-1.4", "M17.7 6.3l1.4-1.4"],
    moon: ["M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z"],
    chevronDown: ["M6 9l6 6 6-6"],
    chevronRight: ["M9 6l6 6-6 6"],
    chevronsLeft: ["M11 17l-5-5 5-5", "M18 17l-5-5 5-5"],
    close: ["M6 6l12 12", "M18 6L6 18"],
    shieldCheck: ["M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z", "M9 12l2 2 4-4"],
    filter: ["M4 6h16", "M7 12h10", "M10 18h4"],
    sparkle: ["M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"],
    minus: ["M8 12h8", "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z"]
};

export function brandMark() {
    return svg("svg", { class: "icon", viewBox: "0 0 24 24", "aria-hidden": "true" }, [
        svg("path", { d: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" }),
        svg("path", { d: "M9 12l2 2 4-4" })
    ]);
}

// ---------- Formatting ----------

const MITRE_NAMES = {
    "T1562.008": "Disable or Modify Cloud Logs",
    "T1562.007": "Disable or Modify Cloud Firewall",
    "T1485": "Data Destruction",
    "T1110": "Brute Force",
    "T1078.004": "Cloud Accounts",
    "T1098.001": "Additional Cloud Credentials",
    "T1530": "Data from Cloud Storage"
};

export const techName = (id) => MITRE_NAMES[id] || "";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function plural(n, word) {
    return n + " " + word + (n === 1 ? "" : "s");
}

export function relTime(epoch, now = Date.now()) {
    const s = Math.max(0, Math.round(now / 1000 - Number(epoch)));
    if (s < 45) return "just now";
    const m = Math.round(s / 60);
    if (m < 60) return plural(m, "minute") + " ago";
    const h = Math.round(s / 3600);
    if (h < 24) return plural(h, "hour") + " ago";
    const d = Math.round(s / 86400);
    if (d < 8) return plural(d, "day") + " ago";
    return shortDate(new Date(Number(epoch) * 1000));
}

// Compact form for narrow screens: 9m, 2h, 3d
export function relTimeShort(epoch, now = Date.now()) {
    const s = Math.max(0, Math.round(now / 1000 - Number(epoch)));
    if (s < 45) return "now";
    const m = Math.round(s / 60);
    if (m < 60) return m + "m ago";
    const h = Math.round(s / 3600);
    if (h < 24) return h + "h ago";
    const d = Math.round(s / 86400);
    return d < 8 ? d + "d ago" : shortDate(new Date(Number(epoch) * 1000));
}

export function shortDate(date) {
    return date.toLocaleDateString("en-US", { month: "short", day: "2-digit", timeZone: "UTC" });
}

// All times are shown in UTC, the same clock the analytics reports use for their days
export function fullDate(epoch) {
    return new Date(Number(epoch) * 1000).toLocaleString("en-US", {
        month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: "UTC"
    }) + " UTC";
}

export function clock(epoch) {
    return new Date(Number(epoch) * 1000).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: "UTC" });
}

export function fmtDuration(seconds) {
    const s = Math.max(0, Math.round(Number(seconds) || 0));
    const m = Math.floor(s / 60);
    return m ? m + "m " + String(s % 60).padStart(2, "0") + "s" : s + "s";
}

export const fmtNum = (n) => Number(n || 0).toLocaleString("en-US");

export const userShort = (arn) => String(arn || "").split("/").pop() || String(arn || "");

export function accountOf(arn) {
    const m = /:(\d{12}):/.exec(String(arn || ""));
    return m ? m[1] : "";
}

export const dayKey = (ms) => new Date(ms).toISOString().slice(0, 10);

export const sevClass = (sev) => String(sev || "").toLowerCase();

export function sevBadge(sev) {
    return el("span", { class: "sev", vars: { "--c": "var(--sev-" + sevClass(sev) + ", var(--text-3))" }, text: sev.charAt(0) + sev.slice(1).toLowerCase() });
}

// Scores are open-ended; these are the detection thresholds (LOW >= 1, MEDIUM >= 200, HIGH >= 400, CRITICAL >= 600)
export function sevOfScore(score) {
    return score >= 600 ? "CRITICAL" : score >= 400 ? "HIGH" : score >= 200 ? "MEDIUM" : "LOW";
}

// ---------- Tooltip ----------

const tip = () => document.getElementById("tip");

export function showTip(event, text) {
    const t = tip();
    t.textContent = text;
    t.hidden = false;
    const x = Math.min(event.clientX + 14, window.innerWidth - t.offsetWidth - 8);
    t.style.left = Math.max(8, x) + "px";
    t.style.top = event.clientY + 16 + "px";
}

export function hideTip() {
    tip().hidden = true;
}

export function attachTip(node, text) {
    node.addEventListener("mousemove", (e) => showTip(e, typeof text === "function" ? text() : text));
    node.addEventListener("mouseleave", hideTip);
}
