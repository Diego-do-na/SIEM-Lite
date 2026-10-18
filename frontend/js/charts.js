// Charts are plain SVG/DOM, no library: nothing to load from a CDN, nothing to patch.
// Colors come from CSS classes and variables, so themes and the Figma palette apply everywhere.

import { el, svg, attachTip, showTip, hideTip, SEVERITIES, sevClass, sevOfScore, shortDate, fmtNum } from "./dom.js";

export function emptyBlock(text) {
    return el("div", { class: "empty", text });
}

function niceStep(max) {
    const raw = max / 4;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const norm = raw / mag;
    const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag;
    return Math.max(1, Math.round(step));
}

function yAxis(root, m, W, H, max) {
    const step = niceStep(max);
    const top = step * 4;
    const ih = H - m.t - m.b;
    for (let i = 0; i <= 4; i++) {
        const y = m.t + ih - (i * step / top) * ih;
        root.appendChild(svg("line", { x1: m.l, x2: W - m.r, y1: y, y2: y, class: "gridline" }));
        root.appendChild(svg("text", { x: m.l - 8, y: y + 4, "text-anchor": "end", text: fmtNum(i * step) }));
    }
    return top;
}

export function legend() {
    return el("div", { class: "legend" }, SEVERITIES.map((s) =>
        el("span", {}, [el("i", { class: "sev-dot", vars: { "--c": "var(--sev-" + sevClass(s) + ")" } }), s.charAt(0) + s.slice(1).toLowerCase()])));
}

// Stacked area, one layer per severity (low at the bottom, critical on top)
export function stackedArea(days, label) {
    const W = 640, H = 250, m = { t: 12, r: 12, b: 28, l: 38 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const n = days.length;
    const order = SEVERITIES.slice().reverse();
    const top = Math.max(1, ...days.map((d) => d.total));
    const root = svg("svg", { class: "chart", viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": label });
    const max = yAxis(root, m, W, H, top);
    const x = (i) => m.l + (n === 1 ? iw / 2 : (i * iw) / (n - 1));
    const y = (v) => m.t + ih - (v / max) * ih;

    let lower = days.map(() => 0);
    order.forEach((sev) => {
        const upper = days.map((d, i) => lower[i] + d[sev]);
        const forward = upper.map((v, i) => x(i) + "," + y(v));
        const backward = lower.map((v, i) => x(i) + "," + y(v)).reverse();
        root.appendChild(svg("polygon", { points: forward.concat(backward).join(" "), class: "layer fill-" + sevClass(sev) }));
        root.appendChild(svg("polyline", { points: forward.join(" "), class: "line stroke-" + sevClass(sev) }));
        lower = upper;
    });

    const every = Math.max(1, Math.ceil(n / 6));
    days.forEach((d, i) => {
        if (i % every !== 0 && i !== n - 1) return;
        if (i !== n - 1 && n - 1 - i < every / 2) return;
        root.appendChild(svg("text", { x: x(i), y: H - 8, "text-anchor": i === 0 ? "start" : i === n - 1 ? "end" : "middle", text: shortDate(new Date(d.day + "T00:00:00Z")) }));
    });

    // One transparent layer reads the pointer and snaps to the nearest day
    const guide = svg("line", { y1: m.t, y2: m.t + ih, class: "guide" });
    guide.setAttribute("visibility", "hidden");
    root.appendChild(guide);
    const hit = svg("rect", { x: m.l, y: m.t, width: iw, height: ih, fill: "transparent" });
    hit.addEventListener("mousemove", (e) => {
        const box = root.getBoundingClientRect();
        const px = ((e.clientX - box.left) / box.width) * W - m.l;
        const i = Math.max(0, Math.min(n - 1, Math.round((px / iw) * (n - 1))));
        const d = days[i];
        guide.setAttribute("x1", x(i));
        guide.setAttribute("x2", x(i));
        guide.setAttribute("visibility", "visible");
        showTip(e, shortDate(new Date(d.day + "T00:00:00Z")) + "\n" + SEVERITIES.map((s) => s.charAt(0) + s.slice(1).toLowerCase() + ": " + d[s]).join("\n") + "\nTotal: " + d.total);
    });
    hit.addEventListener("mouseleave", () => { guide.setAttribute("visibility", "hidden"); hideTip(); });
    root.appendChild(hit);
    return root;
}

// Donut with a legend list. rows: [{label, sub, value}]
export function donut(rows, centerValue, centerLabel, label) {
    if (!rows.length) return emptyBlock("No data in this range");
    const size = 180, r = 68, c = 2 * Math.PI * r;
    const total = rows.reduce((n, row) => n + row.value, 0);
    const root = svg("svg", { class: "chart", viewBox: "0 0 " + size + " " + size, role: "img", "aria-label": label });
    root.appendChild(svg("circle", { cx: size / 2, cy: size / 2, r, class: "seg-ring seg-bg" }));
    let offset = 0;
    rows.forEach((row, i) => {
        const len = Math.max(0, (row.value / total) * c - (rows.length > 1 ? 2 : 0));
        const seg = svg("circle", {
            cx: size / 2, cy: size / 2, r, class: "seg-ring",
            "stroke-dasharray": len + " " + (c - len), "stroke-dashoffset": -offset,
            transform: "rotate(-90 " + size / 2 + " " + size / 2 + ")"
        });
        seg.style.stroke = "var(--cat-" + ((i % 8) + 1) + ")";
        attachTip(seg, row.label + (row.sub ? " " + row.sub : "") + ": " + row.value);
        root.appendChild(seg);
        offset += (row.value / total) * c;
    });
    root.appendChild(svg("text", { x: size / 2, y: size / 2 + 4, "text-anchor": "middle", class: "donut-total", text: fmtNum(centerValue) }));
    root.appendChild(svg("text", { x: size / 2, y: size / 2 + 22, "text-anchor": "middle", class: "donut-cap", text: centerLabel }));

    const list = el("ul", { class: "legend-list" }, rows.map((row, i) =>
        el("li", {}, [
            el("i", { class: "swatch", vars: { "--c": "var(--cat-" + ((i % 8) + 1) + ")" } }),
            el("span", { class: "name" }, [el("b", { text: row.label }), row.sub ? el("small", { text: row.sub }) : null]),
            el("span", { class: "count", text: fmtNum(row.value) })
        ])));
    return el("div", { class: "donut-wrap" }, [root, list]);
}

// Ranked bars. rows: [{label, who, value}]
export function rankedBars(rows) {
    if (!rows.length) return emptyBlock("No data in this range");
    const max = Math.max(...rows.map((r) => r.value));
    return el("div", { class: "bars" }, rows.map((row, i) =>
        el("div", { class: "bar-row" }, [
            el("div", { class: "top" }, [
                el("span", {}, [el("span", { class: "mono", text: row.label }), row.who ? el("span", { class: "who", text: row.who }) : null]),
                el("span", { class: "val", text: fmtNum(row.value) })
            ]),
            el("div", { class: "bar-track" }, [el("div", { class: "bar-fill", vars: { "--w": Math.max(2, (row.value / max) * 100) + "%", "--o": String(1 - i * 0.12) } })])
        ])));
}

// Score histogram. rows: [{low, high, value}], colored by the detection severity thresholds
export function histogram(rows, label) {
    if (!rows.length) return emptyBlock("No data in this range");
    const W = 640, H = 230, m = { t: 12, r: 12, b: 30, l: 38 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const root = svg("svg", { class: "chart", viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": label });
    const max = yAxis(root, m, W, H, Math.max(1, ...rows.map((r) => r.value)));
    const slot = iw / rows.length;
    const bw = Math.min(46, slot - 6);
    rows.forEach((row, i) => {
        const h = (row.value / max) * ih;
        const x = m.l + i * slot + (slot - bw) / 2;
        const rect = svg("rect", { x, y: m.t + ih - h, width: bw, height: Math.max(h, 1), rx: 3, class: "col fill-" + sevClass(sevOfScore(row.low)) });
        attachTip(rect, "Score " + row.low + " to " + row.high + "\n" + fmtNum(row.value) + " incidents");
        root.appendChild(rect);
        root.appendChild(svg("text", { x: x + bw / 2, y: H - 10, "text-anchor": "middle", text: String(row.low) }));
    });
    return root;
}
