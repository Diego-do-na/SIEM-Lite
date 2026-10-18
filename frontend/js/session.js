// The session around the dashboard: the account menu, the sign-out after inactivity (with a warning first),
// and the messages the login screen shows after a session ends. The real access control is the API's authorizer;
// this is about leaving a screen with security data open on an unattended computer.

import { el, icon, ICONS, $, plural } from "./dom.js";

const WARN_SECONDS = 60;
let idle = null;

// ---------- Messages on the login screen ----------

const NOTES = {
    expired: "Your session expired. Sign in again to continue.",
    idle: "You were signed out after a period without activity.",
    "signed-out": "You signed out."
};
export const signOutNote = (reason) => NOTES[reason] || "";

// ---------- Inactivity ----------
// minutes: 0 turns it off. expire(): called when the time is up. Only the person's own input counts as activity,
// not the automatic refresh, and once the warning is up only its buttons keep the session

export function startIdle(minutes, expire) {
    stopIdle();
    if (!minutes) return;
    const limit = minutes * 60000;
    const state = { last: Date.now(), warned: false, timer: null, dialog: null, previous: null };
    const bump = () => { if (!state.warned) state.last = Date.now(); };
    const events = ["pointerdown", "keydown", "wheel", "touchstart", "mousemove"];
    events.forEach((name) => document.addEventListener(name, bump, { passive: true }));

    const hide = () => {
        if (!state.warned) return;
        state.warned = false;
        const box = $("#idle");
        box.hidden = true;
        box.replaceChildren();
        $("#shell").inert = false;
        if (state.previous && document.contains(state.previous)) state.previous.focus({ preventScroll: true });
    };
    const stay = () => { state.last = Date.now(); hide(); };
    const leave = () => { stop(); hide(); expire(); };

    const show = (seconds) => {
        const box = $("#idle");
        if (!state.warned) {
            state.warned = true;
            state.previous = document.activeElement;
            const count = el("b", { id: "idle-count" });
            const stayBtn = el("button", { class: "btn btn-primary", type: "button", text: "Stay signed in", onclick: stay });
            box.replaceChildren(el("div", { class: "idle-box", role: "alertdialog", "aria-modal": "true", "aria-labelledby": "idle-title", "aria-describedby": "idle-text" }, [
                el("span", { class: "idle-ic" }, [icon(ICONS.clock)]),
                el("h2", { id: "idle-title", text: "Still there?" }),
                el("p", { id: "idle-text" }, ["For your security you will be signed out in ", count, " because there has been no activity."]),
                el("div", { class: "idle-actions" }, [stayBtn, el("button", { class: "btn", type: "button", text: "Sign out now", onclick: leave })])
            ]));
            box.hidden = false;
            $("#shell").inert = true;
            stayBtn.focus();
        }
        const count = $("#idle-count");
        if (count) count.textContent = plural(seconds, "second");
    };

    const tick = () => {
        const left = limit - (Date.now() - state.last);
        if (left <= 0) leave();
        else if (left <= WARN_SECONDS * 1000) show(Math.ceil(left / 1000));
        else if (state.warned) hide();
    };
    state.timer = setInterval(tick, 1000);
    const stop = () => {
        clearInterval(state.timer);
        events.forEach((name) => document.removeEventListener(name, bump));
    };
    idle = { stop, hide, minutes };
}

export function stopIdle() {
    if (!idle) return;
    idle.stop();
    idle.hide();
    idle = null;
}

export const idleMinutes = () => (idle ? idle.minutes : 0);

// ---------- Account menu ----------

const since = (ms) => {
    const m = Math.max(0, Math.round((Date.now() - ms) / 60000));
    return m < 1 ? "just now" : m < 60 ? plural(m, "minute") + " ago" : plural(Math.round(m / 60), "hour") + " ago";
};

// info: { name, role, demo, signedAt, idleMinutes }, actions: { theme, signOut }
export function initAccountMenu(getInfo, actions) {
    const button = $("#user-btn");
    const pop = $("#user-pop");
    let isOpen = false;

    const item = (ic, label, run) => el("button", { class: "pop-item", type: "button", role: "menuitem", onclick: () => { close(false); run(); } }, [
        icon(ic), el("span", { text: label })
    ]);

    function render() {
        const info = getInfo();
        pop.replaceChildren(
            el("div", { class: "pop-head" }, [
                el("b", { text: info.name }),
                el("small", { text: info.demo ? "Demo session. No sign-in, generated data" : "Signed in with Amazon Cognito" + (info.role ? " · " + info.role : "") })
            ]),
            el("dl", { class: "pop-facts" }, [
                el("div", {}, [el("dt", { text: "Signed in" }), el("dd", { text: since(info.signedAt) })]),
                el("div", {}, [el("dt", { text: "Inactivity limit" }), el("dd", { text: info.idleMinutes ? info.idleMinutes + " min, with a warning first" : "Off" })])
            ]),
            item(ICONS.sun, "Switch theme", actions.theme),
            item(ICONS.logout, info.demo ? "End demo session" : "Sign out", actions.signOut)
        );
    }

    function onDoc(e) { if (!pop.contains(e.target) && !button.contains(e.target)) close(false); }
    function onKey(e) {
        if (e.key === "Escape") { e.preventDefault(); close(true); }
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            const items = [...pop.querySelectorAll(".pop-item")];
            const at = items.indexOf(document.activeElement);
            e.preventDefault();
            items[(at + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length].focus();
        }
    }
    function openMenu() {
        render();
        pop.hidden = false;
        isOpen = true;
        button.setAttribute("aria-expanded", "true");
        document.addEventListener("pointerdown", onDoc, true);
        document.addEventListener("keydown", onKey);
        window.addEventListener("hashchange", closeQuiet);
        pop.querySelector(".pop-item").focus();
    }
    function close(focusBack) {
        if (!isOpen) return;
        isOpen = false;
        pop.hidden = true;
        button.setAttribute("aria-expanded", "false");
        document.removeEventListener("pointerdown", onDoc, true);
        document.removeEventListener("keydown", onKey);
        window.removeEventListener("hashchange", closeQuiet);
        if (focusBack) button.focus();
    }
    const closeQuiet = () => close(false);
    button.addEventListener("click", () => (isOpen ? close(true) : openMenu()));
    return { close: closeQuiet };
}
