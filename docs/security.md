# Security model of the query path

Scope: the API, Cognito and the dashboard. The security of the detection pipeline itself (least-privilege
roles per Lambda, KMS, SOAR boundaries) is covered in the README.

## Threat model

The API is public by nature: API Gateway exposes a URL on the internet, and so would any desktop client.
The question is not "can it be reached" but "what can a stranger do with it". Design goal: nothing without a
valid token, and nothing destructive even with one (the API is read-only in 1.0).

| Threat | Mitigation |
|---|---|
| Unauthenticated access | JWT authorizer on every route except `/health`. The token is validated by API Gateway (signature, issuer, expiry, audience = app client id) before any Lambda runs, so unauthenticated traffic costs no compute |
| Injection through parameters | Second, independent defense inside each Lambda: severity whitelist, integers parsed and range-checked, text params ≤ 64 chars, `days` ∈ {7,30,90}, cursor decoded and validated, fixed SQL for Athena (only an integer timestamp is interpolated), DynamoDB expressions built with the SDK's condition builders, never string concatenation |
| Stored XSS via event data (attacker-controlled IPs, user names, ARNs) | Frontend writes every API value with `textContent`, never `innerHTML` |
| Token theft via XSS | Strict CSP when served from CloudFront (`script-src 'self'`, `frame-ancestors 'none'`, no inline script); tokens in `sessionStorage` (cleared on tab close) |
| CSRF | Not applicable: authentication is a `Bearer` header added by JavaScript, not a cookie, so the browser never attaches credentials on its own. SameSite cookies are therefore unnecessary |
| DoS / cost abuse | Stage throttling 10 rps / burst 20; Athena per-query cutoff of 1 GiB; cache with 60 s floor; Lambda timeouts (3–29 s) and 128 MB |
| Brute force on login | Cognito hosted UI with its built-in throttling and password policy (12 chars) |
| Information leak in errors | 500 responses return only a `requestId`; details go to CloudWatch via `logger.exception` |
| Over-privileged functions | One IAM role per Lambda. `api_incidents`: Query/GetItem on one table. `api_stats`: Query + cache Get/Put. `api_analytics`: Athena on one workgroup, Glue read, S3 read on processed bucket, S3 write on the Athena results bucket only |
| Wrong-origin browser calls | CORS restricted to `dashboard_origins` (not `*`) |

Two layers on purpose: **token validation** answers "who are you" and lives in API Gateway;
**input validation** answers "is what you sent safe" and lives in the code. A valid user can still send
hostile input, and a bug in one layer should not become a vulnerability.

## Authentication

- Cognito user pool, `username_attributes = email`, admin-create-only (no self sign-up).
- App client without secret (a browser cannot keep one), Authorization Code flow + **PKCE**.
- Scopes `openid email`. Access token 60 min, ID token 60 min, refresh token 30 days.
- Groups `admin` and `viewer`. The first admin is created by Terraform with `alert_email`; Cognito emails a
  temporary password.
- `enable_cli_auth = true` adds `ALLOW_ADMIN_USER_PASSWORD_AUTH` so tokens can be obtained with the AWS CLI
  during testing. **Set it to `false` in any shared or long-lived deployment.**
- MFA is off in 1.0 (planned for 1.1).

## Frontend hosting

Private S3 bucket + CloudFront with Origin Access Control. The bucket is never public; CloudFront is the
only reader. A response-headers policy sets:

- `Content-Security-Policy` (`default-src 'self'`, `connect-src` limited to the API and Cognito domains,
  `frame-ancestors 'none'`, `object-src 'none'`; `style-src` needs `'unsafe-inline'` because the charts set
  inline styles)
- `Strict-Transport-Security`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`

Session handling in the page: tokens live in `sessionStorage`; after `idleMinutes` without activity (30 by default,
`config.js`) a warning dialog appears for 60 seconds and then the session ends and Cognito's logout page is
called. Only the person's own input counts as activity, not the automatic refresh. This limits the time a screen
with security data stays open on an unattended computer; the API's authorizer remains the real access control.

A public URL does not by itself make a static page vulnerable: it contains no secrets and no data (the data
sits behind the API). The real risks are XSS and token handling, covered above. AWS Shield Standard
(included) absorbs volumetric DDoS at the CloudFront edge; WAF rate rules are deferred to 1.1.

## Known gaps (tracked for 1.1)

- MFA for Cognito users.
- AWS WAF in front of CloudFront/API Gateway.
- Rotation of the long-lived IAM access key used for local administration.
- Customer-managed KMS keys for S3, the API log group and DynamoDB (Checkov findings are skipped, with the
  reason, in `.checkov.yaml` or inline).
- API access-log retention is 365 days without a CMK (inline skip `CKV_AWS_158`).
- Throttling is configured at stage level; per-route limits are documented but not exercised.
