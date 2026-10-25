# Roadmap

## 1.0 (current)

Detection, scoring, SOAR-lite, Bedrock triage, incremental analytics, read-only API with Cognito, static
dashboard, Terraform + CI (validate, Checkov, protected `main`).

The dashboard UI is built (overview, incident pages, entities with a page for each IP and user and a region map,
analytics with ATT&CK coverage, response page, search, session handling). It is hosted on private S3 + CloudFront
and was validated against the real API in us-west-2, together with the detection and response paths
(see [testing](testing.md)).

Remaining before tagging 1.0: rotate the `admin01` access key (`scripts/rotate-admin-key.sh`), screenshots in the
README, and the `v1.0` tag.

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
- A longer range for the Athena reports (`ALLOWED_DAYS` is 7/30/90, so "Total" in the dashboard is exact only for
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
