# Roadmap

## 1.0 (current)

Detection, scoring, SOAR-lite, Bedrock triage, incremental analytics, read-only API with Cognito, static
dashboard, Terraform + CI (validate, Checkov, protected `main`).

Remaining before tagging 1.0: validate against real AWS (apply, auth, API, ETL, Athena, dashboard), host
the dashboard on S3 + CloudFront, CloudWatch 4XX/5XX alarm and README update.

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
- AWS Budget and alarms in Terraform.
- Log-group retention for all Lambdas.

## 1.2: product

To be defined after 1.1; candidates: multi-account ingestion, notification channels beyond email, tunable
detection rules from the UI, per-user baselines dashboard.
