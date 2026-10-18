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
same paths as the real API, so loading, filters, pagination and the detail panel all work.

| URL | Shows |
|---|---|
| `?mock=1` | Realistic data for the last 90 days |
| `?mock=empty` | No incidents (empty states) |
| `?mock=error` | The MITRE report fails (per-card error and Retry) |

## Sections

| Route | Data | State |
|---|---|---|
| `#/overview` | `/analytics/severity-trend`, `/analytics/mitre-techniques`, `/incidents`, `/health` | live |
| `#/incidents` | `/incidents` with filters and keyset pagination, `/incidents/{severity}/{timestamp}` | live |
| `#/analytics` | the four `/analytics/*` reports | live |
| `#/reports` | needs a reports endpoint (1.1) | layout only |
| `#/settings` | needs richer `/health` and `POST /actions` (1.1) | layout only |

The 90-day trend is fetched once and sliced for 7, 30 and 90 days, and everything is memoized by the
API's `lastIncidentAt`, so switching tabs or ranges does not call the API again until a new incident arrives.

## Structure

```
index.html            shell (sidebar, top bar, drawer), no inline scripts or styles
styles.css            design tokens first (light and dark), then components
js/main.js            sign-in, routing, theme, polling
js/auth.js            Cognito PKCE
js/api.js, data.js    fetch wrapper and the data layer (endpoints, memo)
js/charts.js          SVG charts (area, donut, bars, histogram)
js/drawer.js          incident detail panel
js/mock.js            demo data, loaded only with ?mock
js/views/             overview, incidents, analytics, reports, settings, shared UI
```

## Restyling

Colors, type and radii are CSS variables at the top of `styles.css` (the palette comes from the Figma
design). Severity colors are used only for severity; technique charts use the separate `--cat-*` ramp.

## Security notes

- Tokens live in `sessionStorage`, not `localStorage`; only the theme and sidebar state use `localStorage`.
- Every value that comes from the API is written with `textContent`; there is no `innerHTML` anywhere.
- No inline scripts, no inline event handlers and no external scripts or fonts, so the page works under
  `script-src 'self'` when it is served from CloudFront with security headers.
