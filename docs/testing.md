# Testing

## Automated (CI)

- `terraform validate` (job "Terraform validate")
- Checkov over `backend/infra` (job "Checkov"): no failed checks; skips are documented

Both are required status checks on `main`; a PR with a failing check cannot be merged (verified with a
deliberately failing PR).

## Lambda logic (local, moto)

The API functions were exercised against moto-mocked DynamoDB, covering:

- keyset pagination over 30 incidents in 5 pages, including ties on the same second across severities
- severity, date range, `ip`, `user`, `technique` filters and invalid input (400)
- detail lookup (found / not found)
- cache behavior: served inside the 60 s floor, served on same version, recomputed on new version or
  after `max_age`
- error path: 500 with `requestId`, no internals in the body

## Against real AWS

Automated with `scripts/smoke-test.sh` (auth, status codes, input validation) and
`scripts/seed-incidents.sh` (synthetic incidents through the stream, exporter, Athena and dashboard).
Checklist:

1. `terraform apply`; outputs present.
2. `GET /health` returns 200 without a token; any other route returns 401.
3. Token from Cognito (CLI or hosted login) → `/incidents`, `/stats`, `/analytics/*` return 200.
4. Insert a synthetic incident into `incident_reports` → raw and processed objects appear → Athena returns
   the row → `lastIncidentAt` changes → the dashboard feed and charts refresh.
5. Bad input: `severity=foo`, `limit=9999`, `days=5`, forged `cursor` → 400.
6. Throttling: burst above 20 requests → some 429.
7. `terraform destroy`.

## Detection and response, validated on real AWS (us-west-2, 25 Oct 2026)

Real API calls from the `admin01` user against the deployed stack, not synthetic events. Each test goes
through EventBridge → detection Lambda → DynamoDB tracker → SNS → SOAR (when critical) → consolidated
incident in the dashboard.

| Test | Action | Result |
|---|---|---|
| StopLogging | `aws cloudtrail stop-logging` | Detected as critical, SNS alert sent, SOAR restarted logging about 2 s after detection. |
| AccessDenied burst | Repeated denied calls (S3/IAM/STS) from one user and IP | Score accumulated per user + IP and crossed the HIGH and CRITICAL thresholds. |
| DeleteTrail | `aws cloudtrail delete-trail` | SOAR recreated the trail from AWS Config history and verified it in about 1-2 min. Only the trail tags were lost. |
| Consolidation | TTL expiry of the tracker item (15 min) | One incident per user + IP, shown in the dashboard as Critical, score 840, T1110 + T1562.008, Mitigated. |

Findings:

- **Bug found and fixed.** The detector crashed on events with `requestParameters: null` (typical of denied
  calls). Fix: `event['detail'].get('requestParameters') or {}`. The failure was silent, which is why the
  1.1 list includes surfacing detector errors.
- **Duplicate alerts.** An alert is sent for every event at HIGH or above, so one burst produces several
  emails. Known; dedupe per window is planned for 1.1.
- **Scores depend on arrival.** A burst of N calls may be scored in partial batches, so intermediate
  scores differ from the final one. The final consolidated score is the reference.
- **Dashboard hosting.** After `terraform apply` the dashboard works from the CloudFront URL: login through
  Cognito, API calls pass CORS.
