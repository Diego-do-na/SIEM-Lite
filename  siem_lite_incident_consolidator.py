import os
import logging
import time
import uuid
import boto3
from boto3.dynamodb.types import TypeDeserializer

deserializer = TypeDeserializer()
dynamodb = boto3.resource('dynamodb')

bedrock_runtime = boto3.client('bedrock-runtime', region_name='us-west-2', config=boto3.session.Config(
    connect_timeout=5,
    read_timeout=15,
    retries={'max_attempts': 1}
))
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Same weights as the detection Lambda, kept in sync for severity recalculation
ACTION_WEIGHTS = {
    'StopLogging': 400,
    'DeleteTrail': 400,
    'DisableKey': 400,
    'ScheduleKeyDeletion': 400,
    'UpdateTrail': 240,
    'DeleteSecurityGroup': 240,
    'AuthorizeSecurityGroupIngress': 200,
    'CreateSecurityGroup': 160,
    'RevokeSecurityGroupIngress': 120,
    'AuthorizeSecurityGroupEgress': 120,
    'RevokeSecurityGroupEgress': 80,
}

# Same critical set as the detection Lambda — only these contribute to
# globalCounts on the configChanges (Rule 1) branch.
CRITICAL_CONFIG_EVENTS = {'StopLogging', 'DeleteTrail', 'DisableKey', 'ScheduleKeyDeletion'}

MITRE_MAP = {
    'StopLogging': 'T1562.008',
    'DeleteTrail': 'T1562.008',
    'UpdateTrail': 'T1562.008',
    'AuthorizeSecurityGroupIngress': 'T1562.007',
    'AuthorizeSecurityGroupEgress': 'T1562.007',
    'RevokeSecurityGroupIngress': 'T1562.007',
    'RevokeSecurityGroupEgress': 'T1562.007',
    'CreateSecurityGroup': 'T1562.007',
    'DeleteSecurityGroup': 'T1562.007',
    'DisableKey': 'T1485',
    'ScheduleKeyDeletion': 'T1485',
}

def get_severity(score):
    if score >= 600:
        return "CRITICAL"
    elif score >= 400:
        return "HIGH"
    elif score >= 200:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "NONE"

def deserialize_item(dynamodb_json):
    return {k: deserializer.deserialize(v) for k, v in dynamodb_json.items()}

def get_mitre_techniques(item):
    """Collect unique MITRE techniques from every action seen in this incident."""
    techniques = set()

    for action_name in item.get('actionCounts', {}).keys():
        technique = MITRE_MAP.get(action_name)
        if technique:
            techniques.add(technique)
        else:
            # Denied-access actions not in the static map get a generic
            # brute-force/discovery technique when repeated.
            techniques.add('T1110')

    for action_name in item.get('configChanges', {}).keys():
        technique = MITRE_MAP.get(action_name)
        if technique:
            techniques.add(technique)

    return sorted(techniques)

def get_action_score_breakdown(item):
    """Build a flat {action_name: score} breakdown, mirroring exactly how
    siem_lite_detection accumulates globalCounts:
    - actionCounts (denied access) always contributes, fallback weight 40.
    - configChanges only contributes if the action is critical; non-critical
      config changes are excluded entirely, since they never added to
      globalCounts in the first place.
    """
    breakdown = {}

    for action_name, details in item.get('actionCounts', {}).items():
        count = int(details.get('count', 0))
        weight = ACTION_WEIGHTS.get(action_name, 40)
        breakdown[action_name] = weight * count

    for action_name, details in item.get('configChanges', {}).items():
        if action_name in CRITICAL_CONFIG_EVENTS:
            count = int(details.get('count', 0))
            weight = ACTION_WEIGHTS.get(action_name, 0)
            breakdown[action_name] = weight * count

    return breakdown

def build_prompt(severity, duration, mitre_techniques, action_counts, config_changes, source_ip, defensive_actions):
    actions_summary = ", ".join(
        f"{action} (x{details.get('count', 0)})"
        for action, details in {**action_counts, **config_changes}.items()
    ) or "no actions recorded"

    techniques_summary = ", ".join(mitre_techniques) if mitre_techniques else "no technique mapped"

    if defensive_actions:
        defensive_summary = "; ".join(
            f"{a['action']} ({'successful' if a.get('success') else 'failed'}: {a.get('detail', 'no detail')})"
            for a in defensive_actions
        )
    else:
        defensive_summary = "no automated action taken"

    return f"""You are a security analyst reviewing an incident already classified by an automated detection system. Generate a brief report with this structure, in **three short, separate paragraphs** (1-2 sentences each, no headers or bullet points):

Paragraph 1: what happened (summarize the activity pattern, don't list every event).
Paragraph 2: why it's notable given the context (severity, duration, volume) and what threat technique it represents (use the MITRE technique name, not just the code).
Paragraph 3: what automated response the system took (if any) and a concrete, actionable recommendation for the security team, considering whether that response already mitigated part of the risk or still requires manual intervention.

Strict rules:
- Don't repeat raw numbers without interpreting them.
- Don't invent information that isn't in the data.
- Be concise: prioritize precision over length.

Incident data:
- Severity: {severity}
- Activity duration: {duration} seconds
- Source IP: {source_ip}
- MITRE ATT&CK techniques involved: {techniques_summary}
- Actions observed: {actions_summary}
- Automated response executed: {defensive_summary}"""

def getBedrockInsight(severity, duration, mitre_techniques, action_counts, config_changes, source_ip, defensive_actions):
    prompt = build_prompt(severity, duration, mitre_techniques, action_counts, config_changes, source_ip, defensive_actions)
    try:
        response = bedrock_runtime.converse(
            modelId = BEDROCK_MODEL_ID,
            messages = [{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig = {"maxTokens": 400, "temperature": 0.3}
        )
        return response['output']['message']['content'][0]['text']
    except Exception as e:
        logger.error(f"Bedrock invocation failed: {str(e)}")
        return "Insight unavailable: automated generation failed. Review the incident manually."


def lambda_handler(event, context):
    incident_table_name = os.environ.get('INCIDENT_TABLE_NAME')
    incident_table = dynamodb.Table(incident_table_name)

    for record in event['Records']:
        try:
            old_image = record['dynamodb']['OldImage']
            item = deserialize_item(old_image)

            first_seen = int(item.get('firstSeen', 0))
            last_seen = int(item.get('lastSeen', 0))
            duration = last_seen - first_seen

            global_score = int(item.get('globalCounts', 0))
            severity = get_severity(global_score)

            mitre_techniques = get_mitre_techniques(item)
            action_score_breakdown = get_action_score_breakdown(item)

            # Add the defensive actions to the incident record for auditing purposes
            defensive_actions = item.get('defensiveActions', [])

            incident_id = str(uuid.uuid4())

            insights = getBedrockInsight(
                severity, duration, mitre_techniques,
                item.get('actionCounts', {}), item.get('configChanges', {}),
                item.get('sourceIPAddress'), defensive_actions
            )

            incident_table.put_item(
                Item={
                    'severity': severity,
                    'timestamp': int(time.time()),
                    'incidentId': incident_id,
                    'userIdentity': item.get('userIdentity'),
                    'sourceIPAddress': item.get('sourceIPAddress'),
                    'globalScore': global_score,
                    'firstSeen': first_seen,
                    'lastSeen': last_seen,
                    'duration': duration,
                    'defensiveActions': defensive_actions,
                    'mitreTechniques': mitre_techniques,
                    'actionCounts': item.get('actionCounts', {}),
                    'configChanges': item.get('configChanges', {}),
                    'actionScores': action_score_breakdown,
                    'insights': insights
                }
            )

            logger.info(f"Incident consolidated and stored: severity={severity}, duration={duration}s")

        except Exception as e:
            logger.error(f"Error processing record: {str(e)}")