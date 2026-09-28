import os
import time
import json
import logging
from collections import Counter

import boto3

athena = boto3.client('athena')
sns = boto3.client('sns')
bedrock_runtime = boto3.client('bedrock-runtime', region_name='us-west-2', config=boto3.session.Config(
    connect_timeout=5,
    read_timeout=15,
    retries={'max_attempts': 1}
))

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ATHENA_DATABASE = os.environ.get('ATHENA_DATABASE')
ATHENA_TABLE = os.environ.get('ATHENA_TABLE')
ATHENA_OUTPUT_LOCATION = os.environ.get('ATHENA_OUTPUT_LOCATION')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID')

WINDOW_SECONDS = 7 * 24 * 3600
POLL_INTERVAL_SECONDS = 1
MAX_POLL_ATTEMPTS = 25  # ~25s max wait for the query


def run_athena_query(since_epoch):
    query = (
        f'SELECT incidentid, severity, globalscore, sourceipaddress, mitretechniques, "timestamp" '
        f'FROM {ATHENA_TABLE} '
        f'WHERE "timestamp" >= {since_epoch}'
    )

    response = athena.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': ATHENA_DATABASE},
        ResultConfiguration={'OutputLocation': ATHENA_OUTPUT_LOCATION}
    )
    query_execution_id = response['QueryExecutionId']

    for _ in range(MAX_POLL_ATTEMPTS):
        status = athena.get_query_execution(QueryExecutionId=query_execution_id)
        state = status['QueryExecution']['Status']['State']

        if state == 'SUCCEEDED':
            return get_all_rows(query_execution_id)
        elif state in ('FAILED', 'CANCELLED'):
            reason = status['QueryExecution']['Status'].get('StateChangeReason', 'unknown')
            raise RuntimeError(f"Athena query {state}: {reason}")

        time.sleep(POLL_INTERVAL_SECONDS)

    raise TimeoutError("Athena query did not complete in time")


def get_all_rows(query_execution_id):
    rows = []
    paginator = athena.get_paginator('get_query_results')
    for page in paginator.paginate(QueryExecutionId=query_execution_id):
        for row in page['ResultSet']['Rows']:
            rows.append([col.get('VarCharValue', '') for col in row['Data']])

    if not rows:
        return []

    header = rows[0]
    return [dict(zip(header, row)) for row in rows[1:]]


def build_aggregates(incidents):
    severity_counts = Counter(i['severity'] for i in incidents)
    ip_counts = Counter(i['sourceipaddress'] for i in incidents if i.get('sourceipaddress'))

    technique_counts = Counter()
    for i in incidents:
        raw = i.get('mitretechniques', '')
        # Athena returns array<varchar> as a bracketed string, e.g. "[T1562.008, T1485]"
        techniques = [t.strip() for t in raw.strip('[]').split(',') if t.strip()]
        technique_counts.update(techniques)

    return {
        'total': len(incidents),
        'by_severity': dict(severity_counts),
        'top_ips': ip_counts.most_common(5),
        'top_techniques': technique_counts.most_common(5),
    }


def build_prompt(aggregates):
    severity_summary = ", ".join(f"{k}: {v}" for k, v in aggregates['by_severity'].items()) or "none"
    ip_summary = ", ".join(f"{ip} (x{count})" for ip, count in aggregates['top_ips']) or "none"
    technique_summary = ", ".join(f"{t} (x{count})" for t, count in aggregates['top_techniques']) or "none"

    return f"""You are a security analyst writing a weekly executive summary for a SOC team, based on aggregated incident statistics (not raw incident data). Write **three short paragraphs** (1-2 sentences each, no headers or bullet points):

Paragraph 1: overall volume and severity distribution this week.
Paragraph 2: notable patterns — repeat source IPs, dominant MITRE ATT&CK techniques (use technique names, not just codes).
Paragraph 3: one concrete recommendation for the team based on these patterns.

Strict rules:
- Don't invent information not present in the data.
- Be concise: prioritize precision over length.

Weekly aggregate data:
- Total incidents: {aggregates['total']}
- Severity breakdown: {severity_summary}
- Top source IPs: {ip_summary}
- Top MITRE techniques: {technique_summary}"""


def get_bedrock_summary(aggregates):
    prompt = build_prompt(aggregates)
    try:
        response = bedrock_runtime.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 400, "temperature": 0.3}
        )
        return response['output']['message']['content'][0]['text']
    except Exception as e:
        logger.error(f"Bedrock invocation failed: {str(e)}")
        return "Summary unavailable: automated generation failed. Review the incident data manually in Athena."


def build_no_activity_message():
    return (
        "SIEM Lite - Weekly Security Report\n\n"
        "No incidents were recorded in the last 7 days. No action needed."
    )


def build_report_message(aggregates, narrative):
    severity_lines = "\n".join(f"  - {k}: {v}" for k, v in aggregates['by_severity'].items())
    ip_lines = "\n".join(f"  - {ip}: {count}" for ip, count in aggregates['top_ips']) or "  - none"
    technique_lines = "\n".join(f"  - {t}: {count}" for t, count in aggregates['top_techniques']) or "  - none"

    return f"""SIEM Lite - Weekly Security Report

Total incidents: {aggregates['total']}

By severity:
{severity_lines}

Top source IPs:
{ip_lines}

Top MITRE techniques:
{technique_lines}

Summary:
{narrative}"""


def lambda_handler(event, context):
    since_epoch = int(time.time()) - WINDOW_SECONDS

    incidents = run_athena_query(since_epoch)
    logger.info(f"Athena returned {len(incidents)} incidents for the last 7 days")

    if not incidents:
        message = build_no_activity_message()
    else:
        aggregates = build_aggregates(incidents)
        narrative = get_bedrock_summary(aggregates)
        message = build_report_message(aggregates, narrative)

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="SIEM Lite - Weekly Security Report",
        Message=message
    )

    logger.info("Weekly report published to SNS")
    return {"statusCode": 200, "body": "Report sent"}