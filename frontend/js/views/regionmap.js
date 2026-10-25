// Region map. Counts incidents per AWS region on a static world outline.
// The list endpoint returns awsRegion per incident (the region most of its calls were made in).

import { el, svg, attachTip, fmtNum, plural } from "../dom.js";
import { MAP_W, MAP_H, LAND, REGION_POINTS } from "../worldmap.js";

export function regionMap(items) {
    const counts = new Map();
    items.forEach((i) => { if (i.awsRegion) counts.set(i.awsRegion, (counts.get(i.awsRegion) || 0) + 1); });
    if (!counts.size) {
        return el("div", { class: "empty", text: "None of the incidents in this range has a region recorded. Incidents created before the region was stored do not show here." });
    }
    const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const peak = ranked[0][1];
    const known = ([region]) => REGION_POINTS[region];
    const nameOf = (region) => (REGION_POINTS[region] ? REGION_POINTS[region][2] : region);

    const root = svg("svg", { class: "map", viewBox: "0 0 " + MAP_W + " " + MAP_H, role: "img", "aria-label": "Incidents by AWS region" }, [
        svg("path", { class: "map-land", d: LAND }),
        ...ranked.filter(known).map(([region, n], index) => {
            const [x, y] = REGION_POINTS[region];
            const r = 5 + 17 * Math.sqrt(n / peak);
            const dot = svg("circle", { class: "map-dot", cx: x, cy: y, r: r.toFixed(1), vars: { "--i": String(index) } });
            attachTip(dot, () => nameOf(region) + " (" + region + "): " + plural(n, "incident"));
            return svg("g", {}, [index === 0 ? svg("circle", { class: "map-ping", cx: x, cy: y, r: r.toFixed(1) }) : null, dot]);
        })
    ]);

    const total = ranked.reduce((n, [, v]) => n + v, 0);
    const list = el("ol", { class: "map-list" }, ranked.slice(0, 7).map(([region, n], index) => el("li", { vars: { "--i": String(index) } }, [
        el("div", { class: "map-row" }, [el("span", {}, [el("b", { class: "mono", text: region }), el("small", { text: nameOf(region) })]), el("span", { class: "map-n", text: fmtNum(n) })]),
        el("div", { class: "bar-track" }, [el("div", { class: "bar-fill", vars: { "--w": Math.max(2, (n / peak) * 100) + "%", "--i": String(index) } })]),
        el("small", { class: "map-pct", text: Math.round((n / total) * 100) + "% of incidents" })
    ])));
    return el("div", { class: "map-wrap" }, [el("div", { class: "map-box" }, [root]), list]);
}
