import json
import os
import logging
import time
import boto3

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
                UpdateExpression = "ADD #cnt :increment SET #t = :ttl_value",
                ExpressionAttributeNames = {
                    '#cnt': 'counter',
                    '#t': 'ttl'
                },
                ExpressionAttributeValues = {
                    ':increment': 1,
                    ':ttl_value': int(time.time()) + (15 * 60)
                },
            )

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'message': 'Internal Server Error'
        }