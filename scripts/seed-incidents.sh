#!/usr/bin/env bash
# Inserts synthetic incidents into the incident_reports table of the deployed stack.
# The DynamoDB Stream then triggers the exporter exactly as for a real incident.
# Usage (from backend/infra):  ../../scripts/seed-incidents.sh
set -euo pipefail
export AWS_PAGER=""   # the AWS CLI v2 pager would wait for a key press

REGION="${AWS_REGION:-us-east-2}"
TABLE=$(terraform output -json dynamodb_tables | python3 -c 'import json,sys; print(json.load(sys.stdin)["incident_reports"])')
RAW=$(terraform output -json s3_buckets | python3 -c 'import json,sys; print(json.load(sys.stdin)["raw"])')
PROCESSED=$(terraform output -json s3_buckets | python3 -c 'import json,sys; print(json.load(sys.stdin)["processed"])')

python3 - "$TABLE" "$REGION" "$RAW" "$PROCESSED" <<'PY'
import json, subprocess, sys, time, uuid
from datetime import datetime, timezone

table, region, raw_bucket, processed_bucket = sys.argv[1:5]
MARK = "Synthetic incident created by seed-incidents.sh for testing."

def aws(*args):
    out = subprocess.run(["aws", *args, "--region", region], check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else {}

# Remove incidents from a previous run (and their exported objects) so runs do not pile up duplicates
old = aws("dynamodb", "scan", "--table-name", table,
          "--filter-expression", "insights = :m",
          "--expression-attribute-values", json.dumps({":m": {"S": MARK}}),
          "--projection-expression", "severity, #t, incidentId",
          "--expression-attribute-names", json.dumps({"#t": "timestamp"})).get("Items", [])
for it in old:
    key = {"severity": it["severity"], "timestamp": it["timestamp"]}
    aws("dynamodb", "delete-item", "--table-name", table, "--key", json.dumps(key))
    d = datetime.fromtimestamp(int(it["timestamp"]["N"]), tz=timezone.utc)
    iid = it["incidentId"]["S"]
    for bucket, k in ((raw_bucket, f"year={d:%Y}/month={d:%m}/day={d:%d}/{iid}.json"),
                      (processed_bucket, f"incidents/day={d:%Y-%m-%d}/{iid}.json")):
        subprocess.run(["aws", "s3api", "delete-object", "--region", region, "--bucket", bucket, "--key", k], check=True, capture_output=True)
print(f"removed {len(old)} previous synthetic incidents")
now = int(time.time())
HOUR, DAY = 3600, 86400

def ddb(v):
    # Minimal python -> DynamoDB JSON
    if isinstance(v, bool): return {"BOOL": v}
    if isinstance(v, (int, float)): return {"N": str(v)}
    if isinstance(v, str): return {"S": v}
    if v is None: return {"NULL": True}
    if isinstance(v, list): return {"L": [ddb(x) for x in v]}
    return {"M": {k: ddb(x) for k, x in v.items()}}

WEIGHTS = {"StopLogging": 400, "DeleteTrail": 400, "DisableKey": 400, "DeleteSecurityGroup": 240,
           "AuthorizeSecurityGroupIngress": 200, "RevokeSecurityGroupIngress": 120, "AccessDenied": 40}
SOURCES = {"StopLogging": "cloudtrail.amazonaws.com", "DeleteTrail": "cloudtrail.amazonaws.com", "DisableKey": "kms.amazonaws.com",
           "AccessDenied": "s3.amazonaws.com"}

def incident(severity, age, ip, user, techniques, actions, response, region):
    # Same shape the detector writes: each action keeps its count, score, region and event source.
    # The score is the sum of the weights, so it always matches the severity thresholds
    ts = now - age
    scores = {a: WEIGHTS[a] * n for a, n in actions.items()}
    return {
        "severity": severity, "timestamp": ts, "incidentId": str(uuid.uuid4()),
        "userIdentity": user, "sourceIPAddress": ip, "globalScore": sum(scores.values()),
        "firstSeen": ts - 600, "lastSeen": ts, "duration": 600,
        "defensiveActions": [{"action": "restart_logging", "success": True}] if response else [],
        "mitreTechniques": techniques,
        "actionCounts": {a: {"count": n, "score": scores[a], "awsRegion": region, "eventSource": SOURCES.get(a, "ec2.amazonaws.com")} for a, n in actions.items()},
        "configChanges": {},
        "actionScores": scores,
        "insights": MARK,
    }

USER = "arn:aws:iam::123456789012:user/test-user"
# Only techniques SIEM Lite really emits: T1562.008 (logs), T1562.007 (firewall), T1485 (keys), T1110 (denied calls)
items = [
    incident("CRITICAL", 5 * 60,         "203.0.113.7",  USER, ["T1110", "T1562.008"], {"StopLogging": 1, "AccessDenied": 11}, True,  "us-east-1"),
    incident("HIGH",     3 * HOUR,       "203.0.113.7",  USER, ["T1110", "T1562.008"], {"DeleteTrail": 1, "AccessDenied": 1},  False, "us-east-1"),
    incident("HIGH",     1 * DAY,        "198.51.100.9", USER, ["T1485"],              {"DisableKey": 1},                      False, "eu-west-1"),
    incident("MEDIUM",   1 * DAY + HOUR, "198.51.100.9", USER, ["T1562.007"],          {"DeleteSecurityGroup": 1},             False, "eu-west-1"),
    incident("MEDIUM",   2 * DAY,        "192.0.2.44",   USER, ["T1562.007"],          {"AuthorizeSecurityGroupIngress": 1},   False, "ap-southeast-1"),
    incident("LOW",      3 * DAY,        "192.0.2.44",   USER, ["T1562.007"],          {"RevokeSecurityGroupIngress": 1},      False, "ap-southeast-1"),
    incident("LOW",      5 * DAY,        "203.0.113.7",  USER, ["T1110"],              {"AccessDenied": 2},                    False, "us-east-1"),
]

for item in items:
    payload = json.dumps({k: ddb(v) for k, v in item.items()})
    subprocess.run(["aws", "dynamodb", "put-item", "--region", region, "--table-name", table, "--item", payload], check=True)
    print(f"inserted {item['severity']:8} ts={item['timestamp']} ip={item['sourceIPAddress']}")
PY
echo "done. Check: aws s3 ls s3://<processed bucket>/incidents/ --recursive"
