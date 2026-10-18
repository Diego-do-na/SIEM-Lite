# Dashboard

Static page, no build step and no dependencies. It signs in with the Cognito hosted page and reads the HTTP API.

```
cp config.example.js config.js     # fill it with `terraform output` of backend/infra
python3 -m http.server 5173
```

Open http://localhost:5173. That origin is the default of `dashboard_origins` in Terraform; if you serve
the page from another origin, add it to that variable before applying.

`config.js` is ignored by git. Nothing in it is a secret (API URL, public client id, login URL), but it is
different for every deployment.

## Demo mode (no AWS needed)

Open `http://localhost:5173/?mock=1` to see the whole dashboard with generated data. The calls go through the
same paths as the real API, so loading, filters, pagination and the incident page all work.
The demo incidents follow the real rules (actions, weights, techniques and automatic responses from `js/mitre.js`, a copy of the backend tables). They are generated from a moment kept per tab, so reloading keeps the same incidents.

| URL | Shows |
|---|---|
| `?mock=1` | Realistic data for the last 90 days. A new incident arrives about every 20 seconds, so the live refresh can be seen |
| `?mock=empty` | No incidents (empty states) |
| `?mock=error` | The MITRE report fails (per-card error and Retry) |

## Sections

| Route | Data | State |
|---|---|---|
| `#/overview` | `/analytics/severity-trend`, `/analytics/mitre-techniques`, `/incidents`, `/health` | live |
| `#/incidents` | `/incidents` with filters and keyset pagination (also `#/incidents?technique=T1485`) | live |
| `#/incidents/<severity>/<timestamp>` | `/incidents/{severity}/{timestamp}`: one incident as a page, with the risk-score ring, score breakdown, SOAR response and timeline | live |
| `#/analytics` | the four `/analytics/*` reports plus statistics computed from `/incidents` (see below), the ATT&CK coverage matrix, and a region map | live; the region map is a preview (the list endpoint has no `awsRegion` until 1.1) |
| `#/reports`, `#/reports/<id>` | needs a reports endpoint (1.1). The list and each report are separate pages | layout only |
| `#/settings` | needs richer `/health` and `POST /actions` (1.1) | layout only |

## MITRE ATT&CK

`js/mitre.js` is the dictionary: the four techniques the detection emits (T1562.008, T1562.007, T1485 and the generic T1110),
the actions that map to each, their weights, and what SOAR does. Select any technique id, on any page, to open its card
(what it is, how it shows up in CloudTrail, how SIEM Lite detects and answers it, how to reduce the risk, and a
"View incidents" link that opens the list filtered by it). If a rule is added in `backend/shared/mitre.py` or `scoring.py`,
add it to this file too.

## Focus mode and the Total range

Selecting a chart (or its expand icon) grows the card to the middle of the screen over a blurred page, with the chart
drawing itself again. It closes only with the X button or Esc, never by clicking outside. The card is moved, not copied
(`js/focus.js`), so live refresh keeps updating it.

The range selector has a **Total** option. Totals by severity are exact (`/stats`, all time). The four Athena reports accept
at most 90 days today, so those cards show the last 90 days and say so (`API_MAX_DAYS` in `js/data.js`; raise it if the
API's `ALLOWED_DAYS` grows). The statistics computed in the browser use the latest 600 incidents.

## Live refresh

Every `pollSeconds` (10 by default, set it in `config.js`) the page calls `/stats`, which is cheap, and compares
`lastIncidentAt`. Only when it changes do the views reload, in place and without skeletons: the totals count up,
new rows are highlighted and a toast says what arrived. The top bar shows the state ("Live · updated 8s ago",
or "Offline" if the call fails), the refresh icon turns while a check runs, and a hidden tab does not poll.
On the Incidents page, if you already loaded more than the first page the list is not replaced; a link offers to reload it.

## Statistics on the Analytics page

The four Athena reports come from the API. The rest (activity by weekday and hour, MITRE tactics, mitigation rate,
top IAM users, duration, techniques by severity and the key figures) is computed in the browser by `js/stats.js` from
up to 600 recent incidents of the selected range (6 pages of 100, memoized like everything else). When there are more,
the card says the figures are an estimate. Moving this to Athena is a 1.1 option if the numbers need to be exact.

The 90-day trend is fetched once and sliced for 7, 30 and 90 days, and everything is memoized by the
API's `lastIncidentAt`, so switching tabs or ranges does not call the API again until a new incident arrives.

## Structure

```
index.html            shell (sidebar, top bar, parameters bar, technique card), no inline scripts or styles
styles.css            design tokens first (light and dark), then components
js/main.js            sign-in, routing, theme, polling
js/auth.js            Cognito PKCE
js/api.js, data.js    fetch wrapper and the data layer (endpoints, memo)
js/charts.js          charts (area, donut, bars, histogram, heatmap, technique matrix)
js/stats.js           statistics computed from incidents (pure functions, no DOM)
js/mitre.js           ATT&CK dictionary, action weights, SOAR answers
js/mitrecard.js       the technique card
js/focus.js           focus mode for chart cards
js/worldmap.js        static world outline and AWS region positions (generated once from Natural Earth)
fonts/                IBM Plex Sans and JetBrains Mono (self-hosted, SIL OFL licenses included)
js/mock.js            demo data, loaded only with ?mock
js/views/             overview, incidents, incident (page), analytics, matrix, regionmap, reports, settings, shared UI
```

## Restyling

Colors, type and radii are CSS variables at the top of `styles.css`. Text is IBM Plex Sans; identifiers, IPs, ARNs and
numbers in tables use JetBrains Mono (`--font` and `--mono`). Severity colors are used only for severity; technique charts use the separate `--cat-*` ramp.

## Motion

Entrances, chart drawing, count-ups and the highlight of new rows are CSS animations and a small `countUp`.
All of it is off for people who set `prefers-reduced-motion`. Keyframes are in the Motion block of `styles.css`.

## Security notes

- Tokens live in `sessionStorage`, not `localStorage`; only the theme and sidebar state use `localStorage`.
- Every value that comes from the API is written with `textContent`; there is no `innerHTML` anywhere.
- No inline scripts, no inline event handlers and no external scripts or fonts (the fonts are in `fonts/`), so the page works under
  `script-src 'self'; font-src 'self'` when it is served from CloudFront with security headers.
