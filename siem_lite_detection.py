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

def get_severity(score):
    if score >= 600:
        return "CRITICO"
    elif score >= 400:
        return "ALTO"
    elif score >= 200:
        return "MEDIO"
    elif score >= 1:
        return "BAJO"

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

        # Checks if the event contains 'errorCode' in its detail, this is important because it indicates from which rule the event comes from.
        if 'errorCode' in event['detail']:
            error_code = event['detail']['errorCode']
            
            # Initialize the DynamoDB table
            table_name = os.environ.get('THRESHOLD_TABLE_NAME')
            table = dynamodb.Table(table_name)

            response = table.update_item(
                Key = {
                    'userIdentity': userARN,
                    'sourceIPAddress': source_ip
                },
                UpdateExpression = (
                    '#gC = if_not_exists(#gC, :increment) + :increment, '
                    '#t = :ttl_value, '
                    # Update the action count for the specific event name. If the action count does not exist, it initializes it to 1 and then increments it by 1.  
                    '#aC.#eN.#c = if_not_exists(#aC.#eN.#c, :one) + :one'
                ),
                ExpressionAttributeNames = {
                    '#eN': event_name,
                    '#aC': 'actionCounts',
                    '#gC': 'globalCounts',
                    '#c': 'count',
                    '#t': 'ttl',
                },
                ExpressionAttributeValues = {
                    # Increment the global count for the user and source IP by the weight of the action. If the action is not defined in ACTION_WEIGHTS, it defaults to 0.
                    ':increment': ACTION_WEIGHTS.get(event_name, 0),
                    ':one': 1,
                    ':ttl_value': int(time.time()) + (15 * 60)
                },
            )



    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'message': 'Internal Server Error'
        }