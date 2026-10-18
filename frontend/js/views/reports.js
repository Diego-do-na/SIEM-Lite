// Reports: layout prepared for the weekly summaries. Not connected to any endpoint yet:
// the weekly summary is only sent by email today, listing it needs a new API route (planned for 1.1).

import { el } from "../dom.js";
import { panel, pageHead } from "./ui.js";

export function mount(root) {
    const list = panel({ title: "Weekly reports", sub: "Executive summaries written by Amazon Bedrock" });
    list.show(el("div", { class: "preview-list", "aria-hidden": "true" }, [1, 2, 3].map(() =>
        el("div", { class: "preview-row" }, [el("span", { class: "bar s" }), el("span", { class: "bar" }), el("span", { class: "pill", text: "Preview" })]))));
    list.note("Reports will be listed here once the API can serve them.");

    const detail = panel({ title: "Report detail", sub: "Full summary, counts by severity and top techniques" });
    detail.show(el("div", { class: "preview-list", "aria-hidden": "true" }, [el("div", { class: "preview-row" }, [el("span", { class: "bar" })]), el("div", { class: "preview-row" }, [el("span", { class: "bar" })]), el("div", { class: "preview-row" }, [el("span", { class: "bar s" })])]));

    root.append(
        pageHead("Reports", "Weekly summaries and, later, downloadable PDFs"),
        el("div", { class: "note" }, [el("span", { text: "Preview only. This section is not connected to any data yet; it is here so the structure is ready when the reports endpoint exists." })]),
        el("div", { class: "grid-2" }, [list.root, detail.root])
    );
    return { refresh() {}, destroy() {} };
}
