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
