import json
import os
import math
import logging
import time
import ipaddress
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

# Define the action weights for different AWS actions. These weights can be used to prioritize or score events based on their severity or importance.
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

# Initialize the DynamoDB resource and the SNS client. The DynamoDB table name and the SNS topic ARN are retrieved from environment variables.
dynamodb = boto3.resource('dynamodb')

# Initialize the SNS client and get the alert topic ARN from environment variables
alert_topic_arn = os.environ.get('ALERT_TOPIC_ARN')
sns = boto3.client('sns')

# Initialize the Lambda client for the SOAR response functionality.
lambda_client = boto3.client('lambda')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define a set of critical configuration events that are considered high-risk or sensitive.
CRITICAL_CONFIG_EVENTS = {'StopLogging', 'DeleteTrail', 'DisableKey', 'ScheduleKeyDeletion'}

# Rule 3: behavior multiplier (time of day + source IP). Optional module.
# Everything is set via env vars; if ENABLE_BEHAVIOR_BASELINE != 'true' the multiplier is always 1.0.

BASELINE_ENABLED = os.environ.get('ENABLE_BEHAVIOR_BASELINE', 'false').lower() == 'true'
BASELINE_TABLE_NAME = os.environ.get('BASELINE_TABLE_NAME')
N0_DAYS = float(os.environ.get('BASELINE_N0_DAYS', '14'))          # days until full confidence
Z_LOW = float(os.environ.get('BASELINE_Z_LOW', '1.0'))             # z clearly normal (s = -1)
Z_HIGH = float(os.environ.get('BASELINE_Z_HIGH', '3.0'))           # z clearly anomalous (s = +1)
TIME_AMPLITUDE = float(os.environ.get('BASELINE_TIME_AMPLITUDE', '0.5'))   # time multiplier: 1 +/- 0.5
IP_BUMP_SAME_RANGE = float(os.environ.get('BASELINE_IP_BUMP_SAME_RANGE', '0.25'))  # new IP, known range
IP_BUMP_NEW_RANGE = float(os.environ.get('BASELINE_IP_BUMP_NEW_RANGE', '0.75'))    # IP in a never-seen range
M_MAX = float(os.environ.get('BASELINE_M_MAX', '2.0'))             # global cap on the product
SIGMA_MIN_RAD = 2 * math.pi / 24                                   # sigma floor: 1 hour

baseline_table = dynamodb.Table(BASELINE_TABLE_NAME) if BASELINE_TABLE_NAME else None


def get_principal_key(user_identity):
    # Must match siem_lite_baseline_updater
    id_type = user_identity.get('type')
    if id_type == 'AssumedRole':
        return user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('arn')
    if id_type in ('IAMUser', 'Root'):
        return user_identity.get('arn')
    return None


def normalize_ip(raw):
    try:
        return str(ipaddress.ip_address(raw))
    except (ValueError, TypeError):
        return None


def parse_event_time(value):
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def load_baseline(principal):
    items = []
    kwargs = {'KeyConditionExpression': Key('userIdentity').eq(principal)}
    while True:
        resp = baseline_table.query(**kwargs)
        items.extend(resp.get('Items', []))
        last_key = resp.get('LastEvaluatedKey')
        if not last_key:
            break
        kwargs['ExclusiveStartKey'] = last_key
    return items


def time_signal(hour_record, event_time):
    # Signal s in [-1, +1]: negative = within normal pattern, positive = outside it
    n = float(hour_record.get('eventCount', 0))
    if n <= 0:
        return 0.0

    s_sum = float(hour_record.get('hourSinSum', 0))
    c_sum = float(hour_record.get('hourCosSum', 0))

    # Mean resultant length R (0 = scattered hours, 1 = always the same hour)
    r = math.sqrt(s_sum ** 2 + c_sum ** 2) / n
    r = min(max(r, 0.05), 1.0)

    mean_angle = math.atan2(s_sum, c_sum)
    sigma = max(math.sqrt(-2 * math.log(r)), SIGMA_MIN_RAD)

    dt = parse_event_time(event_time)
    theta = 2 * math.pi * (dt.hour + dt.minute / 60) / 24

    # Circular angular distance in [0, pi]
    distance = abs((theta - mean_angle + math.pi) % (2 * math.pi) - math.pi)
    z = distance / sigma

    neutral = (Z_LOW + Z_HIGH) / 2
    half_width = (Z_HIGH - Z_LOW) / 2
    return max(-1.0, min(1.0, (z - neutral) / half_width))


def ip_bump(items, source_ip):
    # 0 if known, small if new IP in a known range, large if the range is new
    ip = normalize_ip(source_ip)
    if not ip:
        return 0.0  # AWS service callers: no signal

    known = []
    for item in items:
        record_type = item.get('recordType', '')
        if record_type.startswith('IP#'):
            known.append(record_type[3:])

    if ip in known:
        return 0.0

    ip_obj = ipaddress.ip_address(ip)
    prefix = 24 if ip_obj.version == 4 else 48
    network = ipaddress.ip_network(f'{ip}/{prefix}', strict=False)
    for known_ip in known:
        try:
            if ipaddress.ip_address(known_ip) in network:
                return IP_BUMP_SAME_RANGE
        except ValueError:
            continue
    return IP_BUMP_NEW_RANGE


def get_behavior_multiplier(user_identity, event_time, source_ip, is_critical):
    # Returns 1.0 when disabled, no baseline, or on any error
    if not BASELINE_ENABLED or baseline_table is None:
        return 1.0

    principal = get_principal_key(user_identity)
    if not principal:
        return 1.0

    try:
        items = load_baseline(principal)
        hour_record = next((i for i in items if i.get('recordType') == 'HOUR'), None)
        if not hour_record:
            return 1.0

        confidence = min(1.0, float(hour_record.get('daysSeen', 0)) / N0_DAYS)
        if confidence <= 0:
            return 1.0

        s = time_signal(hour_record, event_time)
        if is_critical:
            s = max(s, 0.0)  # critical actions never go below 1.0
        m_time = 1 + confidence * TIME_AMPLITUDE * s
        m_ip = 1 + confidence * ip_bump(items, source_ip)

        return min(m_time * m_ip, M_MAX)

    except Exception as e:
        logger.error(f"Baseline lookup failed: {type(e).__name__}")
        return 1.0


def apply_multiplier(weight, multiplier):
    # boto3 resource rejects floats: always an int, minimum 1
    return max(1, int(round(weight * multiplier)))


def get_severity(score):
    if score >= 600:
        return "CRITICAL"
    elif score >= 400:
        return "HIGH"
    elif score >= 200:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"

def process_severity(response, user_arn, source_ip, event_name, trail_name, key_id):
    updated_attrs = response.get('Attributes', {})
    global_score = updated_attrs.get('globalCounts')

    if global_score is None:
        return

    severity = get_severity(int(global_score))
    logger.info(f"Severity evaluation completed: {severity}")

    if severity in ["CRITICAL", "HIGH"]:
        alert_time = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        message = (
            f"SIEM Lite Alert - {severity} severity\n"
            f"{'=' * 40}\n\n"
            f"User: {user_arn}\n"
            f"Source IP: {source_ip}\n"
            f"Accumulated score: {global_score}\n"
            f"Detected at: {alert_time}\n\n"
            f"This is a real-time alert based on activity accumulated within the current "
            f"15-minute detection window. A full incident report, including MITRE ATT&CK "
            f"mapping and AI-generated context, will follow once the window closes.\n"
        )

        sns.publish(
            TopicArn=alert_topic_arn,
            Message=message,
            Subject=f"SIEM Lite Alert: {severity} incident - {user_arn.split('/')[-1]}"
        )
        logger.info("SNS alert published successfully")

        # SOAR Response
        if event_name in CRITICAL_CONFIG_EVENTS:
            lambda_client.invoke(
                FunctionName=os.environ.get('SOAR_RESPONSE_FUNCTION_NAME'),
                InvocationType='Event',
                Payload=json.dumps({
                    'user_arn': user_arn,
                    'source_ip': source_ip,
                    'event_name': event_name,
                    'trail_name': trail_name,
                    'key_id': key_id
                    })
            )


def lambda_handler(event, context):
    try:
        # Extracting relevant information from the event
        source = event['source']
        event_name = event['detail']['eventName']
        event_source = event['detail']['eventSource']
        event_time = event['detail']['eventTime']
        aws_region = event['detail']['awsRegion']
        source_ip = event['detail']['sourceIPAddress']
        user_identity = event['detail']['userIdentity']
        userName = user_identity.get('userName')  # assumed roles and root don't have it
        userARN = user_identity['arn']

        # Trail Name if required for StopLogging
        trail_name = event['detail'].get('requestParameters', {}).get('name')

        # KeyId if required for DisableKey and ScheduleKeyDeletion
        key_id = event['detail'].get('requestParameters', {}).get('keyId')

        table_name = os.environ.get('THRESHOLD_TABLE_NAME')
        table = dynamodb.Table(table_name)

        item_key = {
            'userIdentity': userARN,
            'sourceIPAddress': source_ip
        }

        current_timestamp = int(time.time())
        is_critical = event_name in CRITICAL_CONFIG_EVENTS

        if 'errorCode' in event['detail']:
            error_code = event['detail']['errorCode']

            # Rule 3: behavior multiplier on the action weight
            multiplier = get_behavior_multiplier(user_identity, event_time, source_ip, is_critical)
            increment = apply_multiplier(ACTION_WEIGHTS.get(event_name, 40), multiplier)

            table.update_item(
                Key=item_key,
                UpdateExpression='SET #aC = if_not_exists(#aC, :empty_map)',
                ExpressionAttributeNames={'#aC': 'actionCounts'},
                ExpressionAttributeValues={':empty_map': {}}
            )

            table.update_item(
                Key=item_key,
                UpdateExpression='SET #aC.#eN = if_not_exists(#aC.#eN, :empty_map)',
                ExpressionAttributeNames={'#aC': 'actionCounts', '#eN': event_name},
                ExpressionAttributeValues={':empty_map': {}}
            )

            response = table.update_item(
                Key=item_key,
                UpdateExpression=(
                    'SET '
                    '#gC = if_not_exists(#gC, :zero) + :increment, '
                    '#t = :ttl_value, '
                    '#aC.#eN.#c = if_not_exists(#aC.#eN.#c, :zero) + :one, '
                    '#aC.#eN.#sc = if_not_exists(#aC.#eN.#sc, :zero) + :increment, '
                    '#aC.#eN.#ts = list_append(if_not_exists(#aC.#eN.#ts, :empty_list), :new_timestamp), '
                    '#aC.#eN.#es = :event_source, '
                    '#aC.#eN.#ar = :aws_region, '
                    '#fS = if_not_exists(#fS, :event_time), '
                    '#lS = :event_time'
                ),
                ExpressionAttributeNames={
                    '#eN': event_name,
                    '#aC': 'actionCounts',
                    '#gC': 'globalCounts',
                    '#c': 'count',
                    '#sc': 'score',
                    '#ts': 'timestamps',
                    '#es': 'eventSource',
                    '#ar': 'awsRegion',
                    '#t': 'ttl',
                    '#fS': 'firstSeen',
                    '#lS': 'lastSeen'
                },
                ExpressionAttributeValues={
                    ':zero': 0,
                    ':one': 1,
                    ':empty_list': [],
                    ':new_timestamp': [current_timestamp],
                    ':event_source': event_source,
                    ':aws_region': aws_region,
                    ':increment': increment,
                    ':ttl_value': current_timestamp + (15 * 60),
                    ':event_time': current_timestamp
                },
                ReturnValues='UPDATED_NEW'
            )

        else:
            table.update_item(
                Key=item_key,
                UpdateExpression='SET #cC = if_not_exists(#cC, :empty_map)',
                ExpressionAttributeNames={'#cC': 'configChanges'},
                ExpressionAttributeValues={':empty_map': {}}
            )

            table.update_item(
                Key=item_key,
                UpdateExpression='SET #cC.#eN = if_not_exists(#cC.#eN, :empty_map)',
                ExpressionAttributeNames={'#cC': 'configChanges', '#eN': event_name},
                ExpressionAttributeValues={':empty_map': {}}
            )

            global_score_clause = '#gC = if_not_exists(#gC, :zero) + :increment, ' if is_critical else ''
            score_clause = '#cC.#eN.#sc = if_not_exists(#cC.#eN.#sc, :zero) + :increment, ' if is_critical else ''

            expression_names = {
                '#eN': event_name,
                '#cC': 'configChanges',
                '#c': 'count',
                '#ts': 'timestamps',
                '#es': 'eventSource',
                '#ar': 'awsRegion',
                '#t': 'ttl',
                '#fS': 'firstSeen',
                '#lS': 'lastSeen'
            }
            expression_values = {
                ':zero': 0,
                ':one': 1,
                ':empty_list': [],
                ':new_timestamp': [current_timestamp],
                ':event_source': event_source,
                ':aws_region': aws_region,
                ':ttl_value': current_timestamp + (15 * 60),
                ':event_time': current_timestamp
            }

            if is_critical:
                # Rule 3: only critical actions add score, so the baseline is only read here
                multiplier = get_behavior_multiplier(user_identity, event_time, source_ip, is_critical)
                expression_names['#gC'] = 'globalCounts'
                expression_names['#sc'] = 'score'
                expression_values[':increment'] = apply_multiplier(ACTION_WEIGHTS.get(event_name, 0), multiplier)

            response = table.update_item(
                Key=item_key,
                UpdateExpression=(
                    'SET '
                    + global_score_clause
                    + score_clause +
                    '#t = :ttl_value, '
                    '#cC.#eN.#c = if_not_exists(#cC.#eN.#c, :zero) + :one, '
                    '#cC.#eN.#ts = list_append(if_not_exists(#cC.#eN.#ts, :empty_list), :new_timestamp), '
                    '#cC.#eN.#es = :event_source, '
                    '#cC.#eN.#ar = :aws_region, '
                    '#fS = if_not_exists(#fS, :event_time), '
                    '#lS = :event_time'
                ),
                ExpressionAttributeNames=expression_names,
                ExpressionAttributeValues=expression_values,
                ReturnValues='UPDATED_NEW'
            )

        process_severity(response, userARN, source_ip, event_name, trail_name, key_id)

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'message': 'Internal Server Error'
        }