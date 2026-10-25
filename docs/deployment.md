# Deployment and replication

Anyone can fork the repository and deploy it into their own AWS account.

## Prerequisites

- AWS account and credentials with permission to create the resources (IAM, Lambda, DynamoDB, S3, Glue,
  Athena, API Gateway, Cognito, SNS, EventBridge, CloudTrail/Config if enabled).
- Terraform >= 1.5, AWS CLI v2, Python 3.12 (only for local checks).
- Amazon Bedrock access to the model in `bedrock_model_id` (default `us.anthropic.claude-sonnet-4-6`),
  enabled in the target region.

## Variables

Copy `backend/infra/terraform.tfvars.example` to `terraform.tfvars` (git-ignored):

| Variable | Default | Notes |
|---|---|---|
| `aws_region` | none | e.g. `us-east-2` |
| `alert_email` | none | Receives SNS alerts and becomes the first Cognito admin user |
| `enable_behavior_baseline` | none | Rule 3 multiplier |
| `enable_cloudtrail` | `false` | `true` creates the multi-region trail; leave `false` if you already have one |
| `enable_config` | `false` | AWS Config recorder used by SOAR to recreate a deleted trail |
| `enable_event_rules` | `true` | `false` deploys everything without wiring CloudTrail events into detection (safe for testing) |
| `dashboard_origins` | `["http://localhost:5173"]` | Origins allowed by CORS and by the Cognito callback/logout URLs |
| `monthly_budget_usd` | `5` | Account-wide monthly budget; emails `alert_email` at 80% actual and 100% forecast |
| `enable_cli_auth` | `false` | Tokens via CLI, only for testing with `scripts/smoke-test.sh`. Keep `false` for anything shared |

## Deploy

```bash
cd backend/infra
terraform init
terraform validate
terraform plan
terraform apply
terraform output
```

Outputs used later: `api_url`, `cognito_user_pool_id`, `cognito_client_id`, `cognito_login_url`, `frontend_url`.

The dashboard is deployed by the same `apply`: private S3 bucket, CloudFront with Origin Access Control,
security headers, and a `config.js` generated from the other resources. The first CloudFront deploy takes
5-10 minutes. Open `frontend_url` to use it. Editing a file under `frontend/` and running `terraform apply`
uploads the changed objects.

## First login

Cognito emails a temporary password to `alert_email`. Either log in on the hosted page and change it, or
set a permanent one from the CLI:

```bash
aws cognito-idp admin-set-user-password \
  --user-pool-id <cognito_user_pool_id> \
  --username <alert_email> \
  --password '<12+ chars>' --permanent
```

## Run the dashboard locally

```bash
cd frontend
cp config.example.js config.js     # fill with terraform output
python3 -m http.server 5173
```

Open http://localhost:5173. See [frontend/README.md](../frontend/README.md).

## Verify

With `enable_cli_auth = true` in your `terraform.tfvars`, `scripts/smoke-test.sh` runs the checks below
(and `scripts/seed-incidents.sh` inserts synthetic incidents to exercise the whole pipeline):

```bash
cd backend/infra
SMOKE_EMAIL=<alert_email> SMOKE_PASSWORD='<permanent password>' ../../scripts/smoke-test.sh
../../scripts/seed-incidents.sh
```

By hand:

```bash
API=$(terraform output -raw api_url)
curl -s "$API/health"                                   # 200, no token

TOKEN=$(aws cognito-idp admin-initiate-auth \
  --user-pool-id <pool> --client-id <client> \
  --auth-flow ADMIN_USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=<email>,PASSWORD='<password>' \
  --query 'AuthenticationResult.AccessToken' --output text)

curl -s -o /dev/null -w '%{http_code}\n' "$API/incidents"                       # 401
curl -s -H "Authorization: Bearer $TOKEN" "$API/incidents?limit=5"              # 200
curl -s -H "Authorization: Bearer $TOKEN" "$API/stats"
curl -s -H "Authorization: Bearer $TOKEN" "$API/analytics/top-ips?days=7"
```

Test the pipeline end to end by writing a synthetic item to the `incident_reports` table; the stream
triggers the exporter and the object appears under `s3://<processed bucket>/incidents/day=YYYY-MM-DD/`. Then query
it from Athena (database `<prefix>_catalog`, workgroup `<prefix>-workgroup`, table `incidents`).

## Tear down

```bash
terraform destroy
```

The Athena results bucket is removed with its temporary files. The `raw` and `processed` buckets hold
incident data and are deliberately not destroyed while they contain objects: empty them first.

```bash
aws s3 rm s3://<raw bucket> --recursive
aws s3 rm s3://<processed bucket> --recursive
terraform destroy
```

CloudWatch log groups that Lambda creates by itself (`/aws/lambda/<function>`) are not managed by
Terraform and stay behind; delete them by hand if you want the account clean.

## CI

`.github/workflows/ci.yml` runs `terraform validate` and Checkov on every pull request. The `protect-main`
ruleset requires both checks and a pull request to merge into `main`. Accepted Checkov findings are skipped
with a reason, either globally in `backend/infra/.checkov.yaml` or inline next to the resource
(`# checkov:skip=ID:reason`); inline is preferred when the exception applies to a single resource.
