# API reference

Base URL: `terraform output api_url` (API Gateway HTTP API, `$default` stage). All responses are JSON.
Everything except `/health` requires `Authorization: Bearer <access token>` issued by the Cognito user
pool (the **access** token, not the ID token).

| Method | Path | Auth | Lambda |
|---|---|---|---|
| GET | `/health` | none | `api_health` |
| GET | `/incidents` | JWT | `api_incidents` |
| GET | `/incidents/{severity}/{timestamp}` | JWT | `api_incidents` |
| GET | `/stats` | JWT | `api_stats` |
| GET | `/analytics/{report}` | JWT | `api_analytics` |

CORS: allowed origins are `var.dashboard_origins`; methods `GET, OPTIONS`; headers `authorization,
content-type`. The Lambdas do not emit CORS headers, API Gateway does.

## Errors

```json
{ "error": "'severity' must be one of CRITICAL, HIGH, MEDIUM, LOW" }
```

| Code | Meaning |
|---|---|
| 400 | Invalid input (whitelist/range/length validation failed) |
| 401 | Missing, expired or invalid token (returned by API Gateway before any Lambda runs) |
| 404 | Unknown route, unknown report or incident not found |
| 429 | Throttled (10 rps, burst 20) |
| 500 | Unexpected error. Body contains `requestId`; the stack trace is only in CloudWatch |
| 504 | Analytics query did not finish within the function timeout; retry |

## `GET /health`

```json
{ "status": "ok", "time": 1760000000 }
```

## `GET /incidents`

Incidents newest-first across all severities (merged), keyset-paginated.

| Query param | Type | Notes |
|---|---|---|
| `severity` | `CRITICAL\|HIGH\|MEDIUM\|LOW` | optional, case-insensitive |
| `limit` | int 1..100 | default 50 |
| `from`, `to` | epoch seconds | inclusive window on `timestamp` |
| `ip` | text ≤ 64 | prefix match on `sourceIPAddress` |
| `user` | text ≤ 64 | substring match on `userIdentity` |
| `technique` | text ≤ 64 | exact MITRE technique id in `mitreTechniques` |
| `cursor` | opaque | the `nextCursor` of the previous page |

```json
{
  "items": [
    {
      "incidentId": "…", "severity": "HIGH", "timestamp": 1760000000, "globalScore": 140,
      "sourceIPAddress": "203.0.113.7", "userIdentity": "arn:aws:iam::…:user/admin01",
      "mitreTechniques": ["T1562.008"], "duration": 420, "awsRegion": "us-west-2", "responseTaken": true
    }
  ],
  "nextCursor": "eyJ0IjoxNzYw…"
}
```

`awsRegion` is the region where most of the calls of the incident were made (`null` for incidents stored before the region was kept).
`nextCursor` is `null` on the last page. The list leaves out the Bedrock narrative and per-action detail;
fetch those from the detail route.

Pagination notes:

- The cursor encodes `{t: timestamp, s: severity index}`. Ties on the same second are ordered by severity,
  so no item is repeated or skipped between pages.
- `ip`, `user` and `technique` are applied as `FilterExpression` (no secondary index). A search that has to
  read more than 50 pages of the table fails with 400 (`narrow the date range`). For larger volumes the
  search moves to Athena (1.1).

## `GET /incidents/{severity}/{timestamp}`

Full item: score breakdown, MITRE mapping, `defensiveActions`, Bedrock `insights`. `404` if it does not
exist.

## `GET /stats`

```json
{
  "generatedAt": 1760000000,
  "lastIncidentAt": 1759999000,
  "cached": true,
  "windows": {
    "24h": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 5, "LOW": 9, "total": 16 },
    "7d":  { "…": 0 },
    "all": { "…": 0 }
  }
}
```

`lastIncidentAt` is the cache version and the signal the dashboard polls: when it changes, something new
arrived. It is `null` when there are no incidents.

## `GET /analytics/{report}`

`report` ∈ `top-ips`, `mitre-techniques`, `severity-trend`, `score-distribution`.
`days` ∈ `7, 30, 90` (default 30).

```json
{ "report": "top-ips", "days": 30, "generatedAt": 1760000000, "version": 1759999000, "cached": false,
  "data": [ { "ip": "203.0.113.7", "incidents": 4, "maxScore": 180 } ] }
```

| Report | `data` item |
|---|---|
| `top-ips` | `{ip, incidents, maxScore}` (top 10) |
| `mitre-techniques` | `{technique, incidents}` (top 10) |
| `severity-trend` | `{day, CRITICAL, HIGH, MEDIUM, LOW}` |
| `score-distribution` | `{bucket: "100-199", incidents}` |

The SQL is fixed per report. The only interpolated value is `since`, an integer computed in the Lambda;
nothing from the request reaches the query text.
