import json
import os
import logging
import time

import boto3
from boto3.dynamodb.conditions import Key

from shared import scoring, behavior_baseline

# Initialize the DynamoDB resource and the SNS client. The DynamoDB table name and the SNS topic ARN are retrieved from environment variables.
dynamodb = boto3.resource('dynamodb')

# Initialize the SNS client and get the alert topic ARN from environment variables
alert_topic_arn = os.environ.get('ALERT_TOPIC_ARN')
sns = boto3.client('sns')

# Initialize the Lambda client for the SOAR response functionality.
lambda_client = boto3.client('lambda')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Rule 3: behavior multiplier (time of day + source IP). Optional module.
# Everything is set via env vars; if ENABLE_BEHAVIOR_BASELINE != 'true' the multiplier is always 1.0.

BASELINE_ENABLED = os.environ.get('ENABLE_BEHAVIOR_BASELINE', 'false').lower() == 'true'
BASELINE_TABLE_NAME = os.environ.get('BASELINE_TABLE_NAME')
N0_DAYS = float(os.environ.get('BASELINE_N0_DAYS', '14'))          # days until full confidence
TIME_AMPLITUDE = float(os.environ.get('BASELINE_TIME_AMPLITUDE', '0.5'))   # time multiplier: 1 +/- 0.5
M_MAX = float(os.environ.get('BASELINE_M_MAX', '2.0'))             # global cap on the product

baseline_table = dynamodb.Table(BASELINE_TABLE_NAME) if BASELINE_TABLE_NAME else None


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


def get_behavior_multiplier(user_identity, event_time, source_ip, is_critical):
    # Returns 1.0 when disabled, no baseline, or on any error
    if not BASELINE_ENABLED or baseline_table is None:
        return 1.0

    principal = behavior_baseline.get_principal_key(user_identity)
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

        s = behavior_baseline.time_signal(hour_record, event_time)
        if is_critical:
            s = max(s, 0.0)  # critical actions never go below 1.0
        m_time = 1 + confidence * TIME_AMPLITUDE * s
        m_ip = 1 + confidence * behavior_baseline.ip_bump(items, source_ip)

        return min(m_time * m_ip, M_MAX)

    except Exception as e:
        logger.error(f"Baseline lookup failed: {type(e).__name__}")
        return 1.0


def process_severity(response, user_arn, source_ip, event_name, trail_name, key_id):
    updated_attrs = response.get('Attributes', {})
    global_score = updated_attrs.get('globalCounts')

    if global_score is None:
        return

    severity = scoring.get_severity(int(global_score))
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
        if event_name in scoring.CRITICAL_CONFIG_EVENTS:
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
        is_critical = event_name in scoring.CRITICAL_CONFIG_EVENTS

        if 'errorCode' in event['detail']:
            error_code = event['detail']['errorCode']

            # Rule 3: behavior multiplier on the action weight
            multiplier = get_behavior_multiplier(user_identity, event_time, source_ip, is_critical)
            increment = behavior_baseline.apply_multiplier(scoring.ACTION_WEIGHTS.get(event_name, 40), multiplier)

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
                expression_values[':increment'] = behavior_baseline.apply_multiplier(scoring.ACTION_WEIGHTS.get(event_name, 0), multiplier)

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