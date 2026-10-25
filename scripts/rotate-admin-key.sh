#!/usr/bin/env bash
# Rotates the access key of an IAM user in the safe order: create the new key, install it in the AWS CLI
# config, check that it works, and only then delete the old one. If anything fails before the last step,
# the old key is still valid.
# Usage:  AWS_PROFILE=<profile, optional> ./scripts/rotate-admin-key.sh [iam-user, default admin01]
set -euo pipefail
export AWS_PAGER=""

USER_NAME="${1:-admin01}"
# macOS ships bash 3.2, where expanding an empty array under set -u fails, hence the ${arr[@]+...} form below
PROFILE_FLAG=()
[ -n "${AWS_PROFILE:-}" ] && PROFILE_FLAG=(--profile "$AWS_PROFILE")

if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
    echo "AWS_ACCESS_KEY_ID is set in this shell and would override the config file. Unset it and run again." >&2
    exit 1
fi

OLD_ID=$(aws configure get aws_access_key_id ${PROFILE_FLAG[@]+"${PROFILE_FLAG[@]}"})
COUNT=$(aws iam list-access-keys --user-name "$USER_NAME" --query 'length(AccessKeyMetadata)' --output text)
if [ "$COUNT" -ge 2 ]; then
    echo "$USER_NAME already has 2 access keys (the IAM limit). Delete the unused one first." >&2
    exit 1
fi

echo "Rotating the key of $USER_NAME (current: $OLD_ID)"
NEW=$(aws iam create-access-key --user-name "$USER_NAME" --output json)
NEW_ID=$(printf '%s' "$NEW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["AccessKey"]["AccessKeyId"])')
NEW_SECRET=$(printf '%s' "$NEW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["AccessKey"]["SecretAccessKey"])')

aws configure set aws_access_key_id "$NEW_ID" ${PROFILE_FLAG[@]+"${PROFILE_FLAG[@]}"}
aws configure set aws_secret_access_key "$NEW_SECRET" ${PROFILE_FLAG[@]+"${PROFILE_FLAG[@]}"}
unset NEW NEW_SECRET

# A new key can take a few seconds to be accepted everywhere
for attempt in 1 2 3 4 5 6; do
    if ARN=$(aws sts get-caller-identity --query Arn --output text ${PROFILE_FLAG[@]+"${PROFILE_FLAG[@]}"} 2>/dev/null); then break; fi
    sleep 5
done
case "${ARN:-}" in
    *"user/$USER_NAME") echo "New key works: $ARN" ;;
    *) echo "The new key did not work. The old key ($OLD_ID) was NOT deleted; check the config and run again." >&2; exit 1 ;;
esac

aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$OLD_ID"
echo "Old key $OLD_ID deleted. Keys now:"
aws iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata[].[AccessKeyId,Status]' --output text
