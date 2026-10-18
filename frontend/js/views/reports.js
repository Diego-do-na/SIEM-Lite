// Reports: layout prepared for the weekly summaries. Not connected to any endpoint yet:
// the weekly summary is only sent by email today, listing it needs a new API route (planned for 1.1).
//
// Two pages, each a full screen of its own:
//   #/reports          the list of weeks
//   #/reports/<id>     one report, opened as a page (not unfolded inside the list)

import { el, icon, ICONS } from "../dom.js";
import { panel, pageHead } from "./ui.js";

const bar = (cls) => el("span", { class: "bar" + (cls ? " " + cls : "") });

function previewNote() {
    return el("div", { class: "note" }, [el("span", { text: "Preview only. This section is not connected to any data yet; it is here so the structure is ready when the reports endpoint exists." })]);
}

function listPage(root) {
    const rows = [1, 2, 3, 4].map((n) => el("a", { class: "report-row", href: "#/reports/preview-" + n, "aria-label": "Open report preview " + n }, [
        el("span", { class: "doc" }, [icon(ICONS.reports)]),
        el("span", { class: "lines" }, [bar("m"), bar("s")]),
        el("span", { class: "pill", text: "Preview" }),
        el("span", { class: "go" }, [icon(ICONS.chevronRight)])
    ]));
    const list = panel({ title: "Weekly reports", sub: "Executive summaries written by Amazon Bedrock", expandable: false });
    list.show(el("div", { class: "report-list" }, rows));
    list.note("Each report opens on its own page. They will be listed here once the API can serve them.");
    root.append(pageHead("Reports", "Weekly summaries and, later, downloadable PDFs"), previewNote(), list.root);
}

function statBox() {
    return el("div", { class: "card kpi" }, [bar("s"), el("span", { class: "value-ph" }), bar("m")]);
}

function section(title, sub, body) {
    const card = panel({ title, sub, expandable: false });
    card.show(body);
    return card.root;
}

function detailPage(root) {
    const back = el("a", { class: "back", href: "#/reports" }, [icon(ICONS.chevronLeft), "All reports"]);
    const download = el("button", { class: "btn", type: "button", disabled: true }, [icon(ICONS.download), "Download PDF"]);
    root.append(
        back,
        pageHead("Weekly report", "Executive summary for one week, written by Amazon Bedrock", download),
        previewNote(),
        el("div", { class: "grid-stats-4" }, [statBox(), statBox(), statBox(), statBox()]),
        section("Executive summary", "What happened and what it means", el("div", { class: "preview-list", "aria-hidden": "true" }, [
            el("div", { class: "preview-row" }, [bar()]), el("div", { class: "preview-row" }, [bar()]), el("div", { class: "preview-row" }, [bar("m")])
        ])),
        el("div", { class: "grid-2 spaced" }, [
            section("Incidents by severity", "Compared with the previous week", el("div", { class: "preview-list", "aria-hidden": "true" }, [
                el("div", { class: "preview-row" }, [bar()]), el("div", { class: "preview-row" }, [bar("m")]), el("div", { class: "preview-row" }, [bar("s")])
            ])),
            section("Top techniques", "MITRE ATT&CK", el("div", { class: "preview-list", "aria-hidden": "true" }, [
                el("div", { class: "preview-row" }, [bar()]), el("div", { class: "preview-row" }, [bar("m")]), el("div", { class: "preview-row" }, [bar("s")])
            ]))
        ]),
        section("Recommended actions", "Follow-ups suggested by the analysis", el("div", { class: "preview-list", "aria-hidden": "true" }, [
            el("div", { class: "preview-row" }, [bar()]), el("div", { class: "preview-row" }, [bar("m")])
        ]))
    );
}

export function mount(root, ctx) {
    if (ctx.param) detailPage(root);
    else listPage(root);
    return { refresh() {}, destroy() {} };
}
