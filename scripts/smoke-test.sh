#!/usr/bin/env bash
# Smoke test of the deployed API. Usage (from backend/infra, where terraform state lives):
#   SMOKE_EMAIL=you@example.com SMOKE_PASSWORD='...' ../../scripts/smoke-test.sh
# The user must already have a permanent password (log in once on the hosted page, or run with
# SMOKE_SET_PASSWORD=1 to set SMOKE_PASSWORD as the permanent one).
# Needs: aws cli (with credentials), terraform, curl.
set -uo pipefail
export AWS_PAGER=""   # the AWS CLI v2 pager would wait for a key press

: "${SMOKE_EMAIL:?set SMOKE_EMAIL}"
: "${SMOKE_PASSWORD:?set SMOKE_PASSWORD}"

REGION="${AWS_REGION:-us-east-2}"
# Never wait on the terminal or on a stuck connection
awsc() { aws "$@" --cli-connect-timeout 10 --cli-read-timeout 20 </dev/null; }
API=$(terraform output -raw api_url)
POOL=$(terraform output -raw cognito_user_pool_id)
CLIENT=$(terraform output -raw cognito_client_id)

check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS  $1 ($3)"; else echo "FAIL  $1 (expected $2, got $3)"; FAILED=1; fi
}
FAILED=0

if [ "${SMOKE_SET_PASSWORD:-0}" = "1" ]; then
  awsc cognito-idp admin-set-user-password --region "$REGION" --user-pool-id "$POOL" \
    --username "$SMOKE_EMAIL" --password "$SMOKE_PASSWORD" --permanent || exit 1
fi
echo "requesting token..."

TOKEN=$(awsc cognito-idp admin-initiate-auth --region "$REGION" --user-pool-id "$POOL" --client-id "$CLIENT" \
  --auth-flow ADMIN_USER_PASSWORD_AUTH \
  --auth-parameters USERNAME="$SMOKE_EMAIL",PASSWORD="$SMOKE_PASSWORD" \
  --query 'AuthenticationResult.AccessToken' --output text) || exit 1
echo "token length: ${#TOKEN}"

code() { curl -s -o /tmp/smoke_body -w '%{http_code}' "$@"; }

check "GET /health without token"          200 "$(code "$API/health")"
echo "  $(cat /tmp/smoke_body)"
check "GET /incidents without token"       401 "$(code "$API/incidents")"
check "GET /incidents with token"          200 "$(code -H "Authorization: Bearer $TOKEN" "$API/incidents?limit=5")"
echo "  $(cat /tmp/smoke_body)"
check "GET /stats with token"              200 "$(code -H "Authorization: Bearer $TOKEN" "$API/stats")"
echo "  $(cat /tmp/smoke_body)"
check "GET /incidents bad severity"        400 "$(code -H "Authorization: Bearer $TOKEN" "$API/incidents?severity=foo")"
check "GET /incidents bad cursor"          400 "$(code -H "Authorization: Bearer $TOKEN" "$API/incidents?cursor=xxx")"
check "GET /analytics/top-ips bad days"    400 "$(code -H "Authorization: Bearer $TOKEN" "$API/analytics/top-ips?days=5")"
check "GET /analytics/unknown"             404 "$(code -H "Authorization: Bearer $TOKEN" "$API/analytics/unknown")"
check "GET /analytics/top-ips (empty ok)"  200 "$(code -H "Authorization: Bearer $TOKEN" "$API/analytics/top-ips?days=7")"
echo "  $(cat /tmp/smoke_body)"
rm -f /tmp/smoke_body
exit $FAILED
