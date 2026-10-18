// Focus mode: a chart card grows from where it is to the middle of the screen, the page behind blurs and cannot be used.
// It closes only with the X button or Esc, never by clicking outside, so a stray click cannot throw the view away.
// The real card is moved into the overlay (not copied), so it keeps working: a live refresh updates it in place.

import { reducedMotion } from "./dom.js";

let current = null;

const layer = () => document.getElementById("focus");
const holder = () => document.getElementById("focus-holder");
const shell = () => document.getElementById("shell");

export const isFocused = () => current !== null;

function onKey(e) {
    // Esc closes the technique card first when one is open over this view
    if (e.key === "Escape" && document.getElementById("modal").hidden) closeFocus();
}

export function openFocus(root, opener) {
    if (current) return;
    const first = root.getBoundingClientRect();
    // A placeholder keeps the grid from collapsing while the card is away
    const placeholder = document.createElement("div");
    placeholder.className = "focus-ph";
    placeholder.style.height = first.height + "px";
    root.replaceWith(placeholder);
    root.classList.add("expanded");
    holder().appendChild(root);
    layer().hidden = false;
    layer().classList.remove("closing");
    shell().inert = true;
    document.documentElement.classList.add("focus-open");
    document.addEventListener("keydown", onKey);
    current = { root, placeholder, opener };

    const last = root.getBoundingClientRect();
    if (!reducedMotion()) {
        const from = "translate(" + (first.left - last.left) + "px, " + (first.top - last.top) + "px) scale(" + (first.width / last.width) + ", " + (first.height / last.height) + ")";
        root.animate([
            { transformOrigin: "0 0", transform: from, opacity: 0.55 },
            { transformOrigin: "0 0", transform: "none", opacity: 1 }
        ], { duration: 460, easing: "cubic-bezier(.2, .8, .2, 1)" });
        // The chart draws itself again every time it is opened
        root.getAnimations({ subtree: true }).forEach((a) => {
            if (a.animationName && a.effect && a.effect.getComputedTiming().iterations === 1) { a.currentTime = 0; a.play(); }
        });
    }
    const close = root.querySelector(".close-btn");
    if (close) close.focus();
}

export function closeFocus(immediate = false) {
    if (!current) return;
    const { root, placeholder, opener } = current;
    current = null;
    document.removeEventListener("keydown", onKey);
    const finish = () => {
        if (placeholder.isConnected) placeholder.replaceWith(root);
        else root.remove();
        root.classList.remove("expanded");
        layer().hidden = true;
        layer().classList.remove("closing");
        shell().inert = false;
        document.documentElement.classList.remove("focus-open");
        if (opener && document.contains(opener)) opener.focus({ preventScroll: true });
    };
    if (immediate || reducedMotion() || !placeholder.isConnected) {
        finish();
        return;
    }
    const first = root.getBoundingClientRect();
    const last = placeholder.getBoundingClientRect();
    layer().classList.add("closing");
    const to = "translate(" + (last.left - first.left) + "px, " + (last.top - first.top) + "px) scale(" + (last.width / first.width) + ", " + (last.height / first.height) + ")";
    const motion = root.animate([
        { transformOrigin: "0 0", transform: "none", opacity: 1 },
        { transformOrigin: "0 0", transform: to, opacity: 0.4 }
    ], { duration: 340, easing: "cubic-bezier(.4, 0, .2, 1)", fill: "forwards" });
    motion.onfinish = () => { motion.cancel(); finish(); };
}
