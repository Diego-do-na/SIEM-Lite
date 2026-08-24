import json
import os
import logging
import time
import boto3

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

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define a set of critical configuration events that are considered high-risk or sensitive.
CRITICAL_CONFIG_EVENTS = {'StopLogging', 'DeleteTrail', 'DisableKey', 'ScheduleKeyDeletion'}

def get_severity(score):
    if score >= 600:
        return "CRITICAL"
    elif score >= 400:
        return "HIGH"
    elif score >= 200:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"

def process_severity(response, user_arn, source_ip):
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

def lambda_handler(event, context):
    try:
        # Extracting relevant information from the event
        source = event['source']
        event_name = event['detail']['eventName']
        event_source = event['detail']['eventSource']
        event_time = event['detail']['eventTime']
        aws_region = event['detail']['awsRegion']
        source_ip = event['detail']['sourceIPAddress']
        userName = event['detail']['userIdentity']['userName']
        userARN = event['detail']['userIdentity']['arn']

        table_name = os.environ.get('THRESHOLD_TABLE_NAME')
        table = dynamodb.Table(table_name)

        item_key = {
            'userIdentity': userARN,
            'sourceIPAddress': source_ip
        }

        current_timestamp = int(time.time())

        if 'errorCode' in event['detail']:
            error_code = event['detail']['errorCode']

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
                    ':increment': ACTION_WEIGHTS.get(event_name, 40),
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

            is_critical = event_name in CRITICAL_CONFIG_EVENTS

            global_score_clause = '#gC = if_not_exists(#gC, :zero) + :increment, ' if is_critical else ''

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
                expression_names['#gC'] = 'globalCounts'
                expression_values[':increment'] = ACTION_WEIGHTS.get(event_name, 0)

            response = table.update_item(
                Key=item_key,
                UpdateExpression=(
                    'SET '
                    + global_score_clause +
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

        process_severity(response, userARN, source_ip)

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'message': 'Internal Server Error'
        }