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

# Define a set of critical configuration events that are considered high-risk or sensitive. These events may require special attention or monitoring due to their potential impact on the security and integrity of the AWS environment.
CRITICAL_CONFIG_EVENTS = {'StopLogging', 'DeleteTrail', 'DisableKey', 'ScheduleKeyDeletion'}

# Function to determine the severity level based on the score. The severity levels are categorized as follows:
def get_severity(score):
    if score >= 600:
        return "CRITICAL"
    elif score >= 400:
        return "HIGH"
    elif score >= 200:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"

# Declaring the DynamoDB resource
dynamodb = boto3.resource('dynamodb')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

        # Initialize the DynamoDB table
        table_name = os.environ.get('THRESHOLD_TABLE_NAME')
        table = dynamodb.Table(table_name)

        if 'errorCode' in event['detail']:
            error_code = event['detail']['errorCode']

            item_key = {
                'userIdentity': userARN,
                'sourceIPAddress': source_ip
            }

            # Step 1: ensure actionCounts exists as an empty map.
            table.update_item(
                Key = item_key,
                UpdateExpression = 'SET #aC = if_not_exists(#aC, :empty_map)',
                ExpressionAttributeNames = {
                    '#aC': 'actionCounts'
                },
                ExpressionAttributeValues = {
                    ':empty_map': {}
                }
            )

            # Step 2: ensure actionCounts.<eventName> exists as an empty map.
            table.update_item(
                Key = item_key,
                UpdateExpression = 'SET #aC.#eN = if_not_exists(#aC.#eN, :empty_map)',
                ExpressionAttributeNames = {
                    '#aC': 'actionCounts', 
                    '#eN': event_name
                },
                ExpressionAttributeValues = {
                    ':empty_map': {}
                }
            )

            # Step 3: now that the full path exists, update global score, per-action
            # count, ttl, and firstSeen/lastSeen in a single call.
            response = table.update_item(
                Key = item_key,
                UpdateExpression = (
                    'SET '
                    '#gC = if_not_exists(#gC, :zero) + :increment, '
                    '#t = :ttl_value, '
                    '#aC.#eN.#c = if_not_exists(#aC.#eN.#c, :zero) + :one, '
                    '#fS = if_not_exists(#fS, :event_time), '
                    '#lS = :event_time'
                ),
                ExpressionAttributeNames = {
                    '#eN': event_name,
                    '#aC': 'actionCounts',
                    '#gC': 'globalCounts',
                    '#c': 'count',
                    '#t': 'ttl',
                    '#fS': 'firstSeen',
                    '#lS': 'lastSeen'
                },
                ExpressionAttributeValues = {
                    ':zero': 0,
                    ':one': 1,
                    ':increment': ACTION_WEIGHTS.get(event_name, 40),
                    ':ttl_value': int(time.time()) + (15 * 60),
                    ':event_time': int(time.time())
                }
            )
            
        else:
            item_key = {
                'userIdentity': userARN,
                'sourceIPAddress': source_ip
            }

            # Step 1: ensure configChanges exists as an empty map.
            table.update_item(
                Key = item_key,
                UpdateExpression = 'SET #cC = if_not_exists(#cC, :empty_map)',
                ExpressionAttributeNames = {
                    '#cC': 'configChanges',
                },
                ExpressionAttributeValues = {
                    ':empty_map': {}
                }
            )

            # Step 2: ensure configChanges.<eventName> exists as an empty map.
            table.update_item(
                Key = item_key,
                UpdateExpression = 'SET #cC.#eN = if_not_exists(#cC.#eN, :empty_map)',
                ExpressionAttributeNames = {
                    '#cC': 'configChanges', 
                    '#eN': event_name,
                },
                ExpressionAttributeValues = {
                    ':empty_map': {}
                }
            )

            # Step 3: update count, ttl, and firstSeen/lastSeen. Only critical config
            # events also contribute to the real-time global score.
            is_critical = event_name in CRITICAL_CONFIG_EVENTS

            global_score_clause = '#gC = if_not_exists(#gC, :zero) + :increment, ' if is_critical else ''

            expression_names = {
                '#eN': event_name,
                '#cC': 'configChanges',
                '#c': 'count',
                '#t': 'ttl',
                '#fS': 'firstSeen',
                '#lS': 'lastSeen'
            }
            expression_values = {
                ':zero': 0,
                ':one': 1,
                ':ttl_value': int(time.time()) + (15 * 60),
                ':event_time': int(time.time())
            }

            if is_critical:
                expression_names['#gC'] = 'globalCounts'
                expression_values[':increment'] = ACTION_WEIGHTS.get(event_name, 0)

            response = table.update_item(
                Key = item_key,
                UpdateExpression = (
                    'SET '
                    + global_score_clause +
                    '#t = :ttl_value, '
                    '#cC.#eN.#c = if_not_exists(#cC.#eN.#c, :zero) + :one, '
                    '#fS = if_not_exists(#fS, :event_time), '
                    '#lS = :event_time'
                ),
                ExpressionAttributeNames = expression_names,
                ExpressionAttributeValues = expression_values
            )
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'message': 'Internal Server Error'
        }