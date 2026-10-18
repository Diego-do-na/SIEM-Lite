# Roadmap

## 1.0 (current)

Detection, scoring, SOAR-lite, Bedrock triage, incremental analytics, read-only API with Cognito, static
dashboard, Terraform + CI (validate, Checkov, protected `main`).

The dashboard UI is built (overview, incident pages, entities with a page for each IP and user, analytics with ATT&CK coverage, response page,
search, session handling) and runs on demo data (`?mock=1`).

Remaining before tagging 1.0: validate against real AWS (apply, auth, API, ETL, Athena, dashboard, including the
new pages against the real API), host the dashboard on S3 + CloudFront, and README update.

## 1.1: hardening and depth

- MFA for Cognito (TOTP).
- AWS WAF (rate-based rules) on CloudFront / API Gateway.
- Customer-managed KMS keys: S3 buckets, API log group, DynamoDB, Lambda environment; S3 access logging;
  Lambda dead-letter queues. Removes the matching Checkov skips.
- Rotate the long-lived IAM key used for administration; prefer SSO/role-based access.
- Parquet + periodic compaction job (Glue) for the processed layer, with backfill script for existing data.
- `POST /actions` (admin group only): acknowledge/close incident, manual SOAR re-run, with an audit trail.
- Search through Athena when `FilterExpression` stops being viable.
- Atomic counters (updated from the stream) for `/stats` if the table grows.
- Log-group retention for all Lambdas.
- API fields the dashboard is waiting for: `awsRegion` in the incident list (the region map is a preview until then)
  and a longer range for the Athena reports (`ALLOWED_DAYS` is 7/30/90, so "Total" in the dashboard is exact only for
  severity counts; check S3 retention first, then raise `API_MAX_DAYS` in `frontend/js/data.js`).
- Recovery tag (SOAR v2): a resource tagged for recovery gets its configuration saved and can be rebuilt after
  deletion or alteration. Open design questions: tag convention, resource types of the first version, when the
  snapshot is taken (on tagging or periodically), and what to do when the rebuilt resource differs from the original.
  The dashboard's Response page already previews it.
- Incident status workflow (acknowledge, close) and reports in the dashboard (list, view, PDF), both behind the
  `POST /actions` and reports endpoints above.

## 1.2: product

To be defined after 1.1; candidates: multi-account ingestion, notification channels beyond email, tunable
detection rules from the UI, per-user baselines dashboard.
