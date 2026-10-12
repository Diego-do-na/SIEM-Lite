(function () {
    "use strict";

    const cfg = window.SIEM_CONFIG;
    const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    const SEV_VAR = { CRITICAL: "--sev-critical", HIGH: "--sev-high", MEDIUM: "--sev-medium", LOW: "--sev-low" };
    const $ = (id) => document.getElementById(id);
    const NS = "http://www.w3.org/2000/svg";

    const state = { days: 30, lastIncidentAt: null, cursor: null, pollTimer: null };

    // Everything that comes from the API is written with textContent, never as HTML:
    // fields like userIdentity are controlled by whoever generated the event
    function el(tag, props, children) {
        const node = document.createElement(tag);
        Object.entries(props || {}).forEach(([k, v]) => {
            if (k === "text") node.textContent = v;
            else if (k === "style") node.setAttribute("style", v);
            else node.setAttribute(k, v);
        });
        (children || []).forEach((c) => node.appendChild(c));
        return node;
    }

    function svg(tag, attrs, text) {
        const node = document.createElementNS(NS, tag);
        Object.entries(attrs || {}).forEach(([k, v]) => node.setAttribute(k, v));
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function showBanner(message) {
        const b = $("banner");
        b.textContent = message;
        b.hidden = !message;
    }

    // ---------- Auth: Cognito hosted login, authorization code + PKCE ----------

    const redirectUri = window.location.origin + "/";

    function b64url(bytes) {
        return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function randomString(len) {
        return b64url(crypto.getRandomValues(new Uint8Array(len))).slice(0, len);
    }

    async function login() {
        const verifier = randomString(64);
        const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
        const stateParam = randomString(16);
        sessionStorage.setItem("pkce_verifier", verifier);
        sessionStorage.setItem("pkce_state", stateParam);

        const params = new URLSearchParams({
            response_type: "code",
            client_id: cfg.clientId,
            redirect_uri: redirectUri,
            scope: "openid email",
            code_challenge: challenge,
            code_challenge_method: "S256",
            state: stateParam
        });
        window.location.href = cfg.loginUrl + "/oauth2/authorize?" + params.toString();
    }

    async function tokenRequest(body) {
        const res = await fetch(cfg.loginUrl + "/oauth2/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams(body).toString()
        });
        if (!res.ok) throw new Error("Login failed (" + res.status + ")");
        return res.json();
    }

    function saveTokens(tokens) {
        sessionStorage.setItem("access_token", tokens.access_token);
        sessionStorage.setItem("expires_at", String(Date.now() + (tokens.expires_in - 60) * 1000));
        if (tokens.refresh_token) sessionStorage.setItem("refresh_token", tokens.refresh_token);
    }

    async function handleRedirect() {
        const params = new URLSearchParams(window.location.search);
        if (!params.has("code")) return;

        const expected = sessionStorage.getItem("pkce_state");
        const verifier = sessionStorage.getItem("pkce_verifier");
        window.history.replaceState({}, "", window.location.pathname);
        if (!verifier || params.get("state") !== expected) throw new Error("Unexpected login response, try again");

        saveTokens(await tokenRequest({
            grant_type: "authorization_code",
            client_id: cfg.clientId,
            code: params.get("code"),
            redirect_uri: redirectUri,
            code_verifier: verifier
        }));
        sessionStorage.removeItem("pkce_verifier");
        sessionStorage.removeItem("pkce_state");
    }

    async function getToken() {
        const token = sessionStorage.getItem("access_token");
        if (token && Date.now() < Number(sessionStorage.getItem("expires_at"))) return token;

        const refresh = sessionStorage.getItem("refresh_token");
        if (!refresh) return null;
        try {
            saveTokens(await tokenRequest({ grant_type: "refresh_token", client_id: cfg.clientId, refresh_token: refresh }));
            return sessionStorage.getItem("access_token");
        } catch (e) {
            sessionStorage.clear();
            return null;
        }
    }

    function logout() {
        sessionStorage.clear();
        const params = new URLSearchParams({ client_id: cfg.clientId, logout_uri: redirectUri });
        window.location.href = cfg.loginUrl + "/logout?" + params.toString();
    }

    async function api(path) {
        const token = await getToken();
        if (!token) {
            showLogin();
            throw new Error("Not signed in");
        }
        const res = await fetch(cfg.apiUrl + path, { headers: { Authorization: "Bearer " + token } });
        if (res.status === 401) {
            sessionStorage.clear();
            showLogin();
            throw new Error("Session expired");
        }
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || "Request failed (" + res.status + ")");
        return body;
    }

    // ---------- Helpers ----------

    function fmtTime(epoch) {
        return new Date(Number(epoch) * 1000).toLocaleString();
    }

    function sevBadge(sev) {
        return el("span", { class: "sev sev-" + sev.toLowerCase(), style: "--c: var(" + (SEV_VAR[sev] || "--text-3") + ")", text: sev });
    }

    const tip = $("tip");
    function attachTip(node, text) {
        node.addEventListener("mousemove", (e) => {
            tip.textContent = text;
            tip.hidden = false;
            tip.style.left = e.clientX + 12 + "px";
            tip.style.top = e.clientY + 12 + "px";
        });
        node.addEventListener("mouseleave", () => { tip.hidden = true; });
    }

    // ---------- Stats ----------

    function renderStats(stats) {
        const tiles = $("tiles");
        tiles.replaceChildren();
        [
            ["Last 24 hours", stats.windows["24h"].total, "incidents"],
            ["Last 7 days", stats.windows["7d"].total, "incidents"],
            ["All time", stats.windows.all.total, "incidents"],
            ["Last incident", stats.lastIncidentAt ? fmtTime(stats.lastIncidentAt) : "None yet", ""]
        ].forEach(([label, value, sub]) => {
            const big = typeof value === "number";
            tiles.appendChild(el("div", { class: "tile" }, [
                el("div", { class: "label", text: label }),
                el("div", { class: "value", text: String(value), style: big ? "" : "font-size:15px;padding:7px 0" }),
                el("div", { class: "sub", text: sub })
            ]));
        });

        const legend = $("legend");
        legend.replaceChildren(...SEVERITIES.map((s) => el("span", { style: "--c: var(" + SEV_VAR[s] + ")", text: s })));

        const rows = $("windows");
        rows.replaceChildren();
        [["24h", "24 hours"], ["7d", "7 days"], ["all", "All time"]].forEach(([key, name]) => {
            const w = stats.windows[key];
            const stack = el("div", { class: "stack" });
            SEVERITIES.forEach((s) => {
                if (!w[s]) return;
                const seg = el("div", { style: "--c: var(" + SEV_VAR[s] + "); flex: " + w[s] });
                attachTip(seg, s + ": " + w[s]);
                stack.appendChild(seg);
            });
            rows.appendChild(el("div", { class: "win-row" }, [
                el("div", { class: "name", text: name }),
                stack,
                el("div", { class: "total", text: String(w.total) })
            ]));
        });
    }

    // ---------- Incidents ----------

    function incidentRow(item) {
        const tr = el("tr", {}, [
            el("td", { text: fmtTime(item.timestamp) }),
            el("td", {}, [sevBadge(item.severity)]),
            el("td", { text: String(item.globalScore ?? "") }),
            el("td", { text: item.sourceIPAddress || "" }),
            el("td", { text: item.userIdentity || "" }),
            el("td", { text: (item.mitreTechniques || []).join(", ") }),
            el("td", { text: item.responseTaken ? "Yes" : "No" })
        ]);
        tr.addEventListener("click", () => openDetail(item.severity, item.timestamp));
        return tr;
    }

    function fillTable(tableId, items, append, emptyText) {
        const body = document.querySelector("#" + tableId + " tbody");
        if (!append) body.replaceChildren();
        if (!items.length && !append) {
            body.appendChild(el("tr", {}, [el("td", { colspan: "7", class: "empty", text: emptyText })]));
        }
        items.forEach((item) => body.appendChild(incidentRow(item)));
    }

    // Main feed: the newest page only. The history section below pages through everything
    async function loadFeed() {
        const data = await api("/incidents?limit=15");
        fillTable("incidents", data.items, false, "No incidents yet");
    }

    function dayStart(value) {
        return Math.floor(new Date(value + "T00:00:00").getTime() / 1000);
    }

    function historyParams(append) {
        const params = new URLSearchParams({ limit: "50" });
        const fields = { severity: "h-severity", ip: "h-ip", user: "h-user", technique: "h-technique" };
        Object.entries(fields).forEach(([name, id]) => {
            const value = $(id).value.trim();
            if (value) params.set(name, value);
        });
        if ($("h-from").value) params.set("from", String(dayStart($("h-from").value)));
        // End of the chosen day, in the browser's time zone
        if ($("h-to").value) params.set("to", String(dayStart($("h-to").value) + 86399));
        if (append && state.cursor) params.set("cursor", state.cursor);
        return params;
    }

    async function loadHistory(append) {
        const data = await api("/incidents?" + historyParams(append).toString());
        fillTable("history-table", data.items, append, "No incidents match");
        state.cursor = data.nextCursor;
        $("more").hidden = !data.nextCursor;
    }

    async function openDetail(severity, timestamp) {
        const body = $("drawer-body");
        body.replaceChildren(el("p", { text: "Loading..." }));
        $("drawer").hidden = false;
        try {
            const i = await api("/incidents/" + encodeURIComponent(severity) + "/" + encodeURIComponent(timestamp));
            const rows = [
                ["Incident", i.incidentId], ["Severity", i.severity], ["Score", i.globalScore],
                ["Detected", fmtTime(i.timestamp)], ["First seen", fmtTime(i.firstSeen)], ["Last seen", fmtTime(i.lastSeen)],
                ["Duration", i.duration + " s"], ["Source IP", i.sourceIPAddress], ["User", i.userIdentity],
                ["Techniques", (i.mitreTechniques || []).join(", ")]
            ];
            const dl = el("dl", { class: "kv" });
            rows.forEach(([k, v]) => {
                dl.appendChild(el("dt", { text: k }));
                dl.appendChild(el("dd", { text: v === undefined || v === null ? "" : String(v) }));
            });

            const actions = Object.entries(i.actionCounts || {}).map(([name, d]) => name + " x" + (d && d.count !== undefined ? d.count : "?"));
            const changes = Object.entries(i.configChanges || {}).map(([name, d]) => name + " x" + (d && d.count !== undefined ? d.count : "?"));
            const defensive = (i.defensiveActions || []).map((a) => a.action + " (" + (a.success ? "ok" : "failed") + ")" + (a.detail ? ": " + a.detail : ""));

            body.replaceChildren(
                el("h2", { text: "Incident detail" }), dl,
                el("h3", { text: "Observed actions" }), el("p", { text: actions.concat(changes).join(", ") || "None" }),
                el("h3", { text: "Automated response" }), el("p", { text: defensive.join("; ") || "None" }),
                el("h3", { text: "Analyst summary" }), el("p", { class: "insight", text: i.insights || "No summary" })
            );
        } catch (e) {
            body.replaceChildren(el("p", { text: e.message }));
        }
    }

    // ---------- Charts (plain SVG) ----------

    function emptyChart(container) {
        container.replaceChildren(el("div", { class: "empty", text: "No data in this range" }));
    }

    function barsH(container, rows, label) {
        if (!rows.length) return emptyChart(container);
        const rowH = 26, left = 120, right = 40, width = 400;
        const max = Math.max(...rows.map((r) => r.value));
        const root = svg("svg", { viewBox: "0 0 " + width + " " + rows.length * rowH, role: "img", "aria-label": label });
        rows.forEach((r, idx) => {
            const y = idx * rowH;
            const w = Math.max(2, ((width - left - right) * r.value) / max);
            root.appendChild(svg("text", { x: left - 8, y: y + 16, "text-anchor": "end" }, r.label.length > 18 ? r.label.slice(0, 17) + "…" : r.label));
            const bar = svg("rect", { x: left, y: y + 4, width: w, height: 16, rx: 3, class: "bar" });
            attachTip(bar, r.label + ": " + r.value);
            root.appendChild(bar);
            root.appendChild(svg("text", { x: left + w + 6, y: y + 16 }, String(r.value)));
        });
        container.replaceChildren(root);
    }

    function columns(container, rows, label) {
        if (!rows.length) return emptyChart(container);
        const width = 400, height = 180, top = 12, bottom = 28, left = 8;
        const max = Math.max(...rows.map((r) => r.value));
        const slot = (width - left) / rows.length;
        const bw = Math.min(40, slot - 6);
        const root = svg("svg", { viewBox: "0 0 " + width + " " + height, role: "img", "aria-label": label });
        root.appendChild(svg("line", { x1: left, x2: width, y1: height - bottom, y2: height - bottom, class: "grid-line" }));
        rows.forEach((r, idx) => {
            const h = ((height - top - bottom) * r.value) / max;
            const x = left + idx * slot + (slot - bw) / 2;
            const bar = svg("rect", { x, y: height - bottom - h, width: bw, height: Math.max(h, 2), rx: 3, class: "bar" });
            attachTip(bar, r.label + ": " + r.value);
            root.appendChild(bar);
            root.appendChild(svg("text", { x: x + bw / 2, y: height - 10, "text-anchor": "middle" }, r.label.split("-")[0]));
        });
        container.replaceChildren(root);
    }

    function trend(container, days) {
        if (!days.length) return emptyChart(container);
        const width = 400, height = 180, top = 12, bottom = 28, left = 8;
        const totals = days.map((d) => SEVERITIES.reduce((n, s) => n + d[s], 0));
        const max = Math.max(...totals);
        const slot = (width - left) / days.length;
        const bw = Math.min(28, slot - 4);
        const root = svg("svg", { viewBox: "0 0 " + width + " " + height, role: "img", "aria-label": "Incidents per day by severity" });
        root.appendChild(svg("line", { x1: left, x2: width, y1: height - bottom, y2: height - bottom, class: "grid-line" }));
        const every = Math.ceil(days.length / 6);
        days.forEach((d, idx) => {
            const x = left + idx * slot + (slot - bw) / 2;
            let y = height - bottom;
            SEVERITIES.slice().reverse().forEach((s) => {
                if (!d[s]) return;
                const h = ((height - top - bottom) * d[s]) / max;
                y -= h;
                const seg = svg("rect", { x, y, width: bw, height: h - 1, rx: 2, style: "fill: var(" + SEV_VAR[s] + ")" });
                attachTip(seg, d.day + " " + s + ": " + d[s]);
                root.appendChild(seg);
            });
            if (idx % every === 0) root.appendChild(svg("text", { x: x + bw / 2, y: height - 10, "text-anchor": "middle" }, d.day.slice(5)));
        });
        container.replaceChildren(root);
    }

    async function loadAnalytics() {
        const q = "?days=" + state.days;
        const reports = [
            ["severity-trend", (data) => trend($("chart-trend"), data)],
            ["top-ips", (data) => barsH($("chart-ips"), data.map((r) => ({ label: r.ip, value: r.incidents })), "Top source IPs")],
            ["mitre-techniques", (data) => barsH($("chart-mitre"), data.map((r) => ({ label: r.technique, value: r.incidents })), "MITRE techniques")],
            ["score-distribution", (data) => columns($("chart-scores"), data.map((r) => ({ label: r.bucket, value: r.incidents })), "Score distribution")]
        ];
        // Sequential on purpose: the first call fills the cache and the API throttles bursts
        let generatedAt = 0;
        let failure = null;
        for (const [name, draw] of reports) {
            try {
                const res = await api("/analytics/" + name + q);
                draw(res.data);
                generatedAt = Math.max(generatedAt, res.generatedAt);
            } catch (err) {
                // Keep going: one slow or failing report must not hide the others
                failure = err;
            }
        }
        if (generatedAt) {
            $("analytics-note").textContent = "Computed " + fmtTime(generatedAt) + ". Recomputed when a new incident arrives.";
        }
        if (failure) throw failure;
    }

    // ---------- Flow ----------

    function showLogin() {
        $("app").hidden = true;
        $("login").hidden = false;
        $("logout").hidden = true;
        $("live").hidden = true;
        if (state.pollTimer) clearInterval(state.pollTimer);
    }

    async function poll() {
        try {
            const stats = await api("/stats");
            renderStats(stats);
            if (state.lastIncidentAt !== null && stats.lastIncidentAt !== state.lastIncidentAt) {
                await Promise.all([loadFeed(), loadAnalytics()]);
            }
            state.lastIncidentAt = stats.lastIncidentAt;
            showBanner("");
        } catch (e) {
            if (e.message !== "Not signed in" && e.message !== "Session expired") showBanner(e.message);
        }
    }

    async function start() {
        $("login").hidden = true;
        $("app").hidden = false;
        $("logout").hidden = false;
        $("live").hidden = false;
        try {
            const stats = await api("/stats");
            renderStats(stats);
            state.lastIncidentAt = stats.lastIncidentAt;
            await loadFeed();
            await loadAnalytics();
            await loadHistory(false);
        } catch (e) {
            if (e.message !== "Not signed in" && e.message !== "Session expired") showBanner(e.message);
        }
        state.pollTimer = setInterval(poll, (cfg.pollSeconds || 10) * 1000);
    }

    function bind() {
        $("login-btn").addEventListener("click", login);
        $("logout").addEventListener("click", logout);
        $("drawer-close").addEventListener("click", () => { $("drawer").hidden = true; });
        $("history-form").addEventListener("submit", (e) => {
            e.preventDefault();
            state.cursor = null;
            loadHistory(false).catch((err) => showBanner(err.message));
        });
        $("h-reset").addEventListener("click", () => {
            $("history-form").reset();
            state.cursor = null;
            loadHistory(false).catch((err) => showBanner(err.message));
        });
        $("more").addEventListener("click", () => loadHistory(true).catch((err) => showBanner(err.message)));
        $("days").addEventListener("click", (e) => {
            const btn = e.target.closest("button");
            if (!btn) return;
            state.days = Number(btn.dataset.days);
            document.querySelectorAll("#days button").forEach((b) => b.classList.toggle("on", b === btn));
            loadAnalytics().catch((err) => showBanner(err.message));
        });
    }

    async function main() {
        bind();
        if (!cfg) {
            showBanner("Missing config.js: copy config.example.js and fill it with the Terraform outputs.");
            return;
        }
        try {
            await handleRedirect();
        } catch (e) {
            showBanner(e.message);
        }
        if (await getToken()) start();
        else showLogin();
    }

    main();
})();
