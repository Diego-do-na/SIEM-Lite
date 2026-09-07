import json
import os
import logging
import time
import boto3

# Initialize the CloudTrail client for interacting with AWS CloudTrail.
cloudtrail = boto3.client('cloudtrail')

# Initialize the DynamoDB resource for storing defensive action records.
dynamodb = boto3.resource('dynamodb')

# Initialize the KMS client for interacting with AWS KMS.
kms_client = boto3.client('kms')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    try:
        # Extracting relevant information from the event payload sent by the detection Lambda
        event_name = event['event_name']
        trail_name = event.get('trail_name')
        key_id = event.get('key_id')
        user_arn = event['user_arn']
        source_ip = event['source_ip']

        # Get a handle to Table 1 once, reused below for both the read and the final write.
        table_name = os.environ.get('THRESHOLD_TABLE_NAME')
        table = dynamodb.Table(table_name)

        # Read the current item so the defensive actions below can inspect prior state (e.g. previous defensiveActions, threshold counters) before deciding/recording anything.
        current_item = table.get_item(
            Key={
                'userIdentity': user_arn,
                'sourceIPAddress': source_ip
            }
        ).get('Item', {})

        # Avoid repeating the same defensive action if it was already recorded for this userIdentity/sourceIPAddress pair.
        existing_actions = current_item.get('defensiveActions', [])
        already_handled = False
        for a in existing_actions:
            if a.get('action') == event_name:
                already_handled = True
                break

        if already_handled:
            logger.info(f"Defensive action for {event_name} already handled for user {user_arn} from IP {source_ip}. Skipping.")
            return {
                'message': 'Defensive action already handled',
                'record': None
            }

        # StopLogging defensive action: If the event is a StopLogging action, we attempt to restart logging for the specified trail.
        if event_name == "StopLogging":
            try:
                cloudtrail.start_logging(Name=trail_name)
                action_success = True
                action_detail = "Trail logging restarted successfully"
            except Exception as e:
                action_success = False
                action_detail = f"Failed to restart logging: {str(e)}"
                logger.error(action_detail)

        # KMS defensive actions: If the event is a DisableKey or ScheduleKeyDeletion action, we attempt to re-enable the key or cancel its deletion.
        elif event_name in ["DisableKey", "ScheduleKeyDeletion"]:
            try:
                if event_name == "DisableKey":
                    kms_client.enable_key(KeyId=key_id)
                    action_success = True
                    action_detail = "KMS key re-enabled successfully"
                elif event_name == "ScheduleKeyDeletion":
                    kms_client.cancel_key_deletion(KeyId=key_id)
                    action_success = True
                    action_detail = "KMS key deletion canceled successfully"
            except Exception as e:
                action_success = False
                action_detail = f"Failed to perform SOAR action: {str(e)}"
                logger.error(action_detail)
        
        # DeleteTrail defensive action: If the event is a DeleteTrail action, we attempt to recreate the trail with the same configuration.
        elif event_name == "DeleteTrail":
            action_success = False
            action_detail = "No automatic remediation possible: trail was deleted and cannot be recreated without AWS Config storing its prior configuration"
        
        # The summary of the defensive action taken is recorded in the DynamoDB table for future reference and auditing.
        action_record = {
            'action': event_name,
            'targetResource': trail_name or key_id,
            'success': action_success,
            'detail': action_detail,
            'timestamp': int(time.time())
        }

        response = table.update_item(
            Key={
                'userIdentity': user_arn,
                'sourceIPAddress': source_ip
            },
            UpdateExpression=(
                'SET '
                '#dA = list_append(if_not_exists(#dA, :empty_list), :new_action)'
            ),
            ExpressionAttributeNames={
                '#dA': 'defensiveActions'
            },
            ExpressionAttributeValues={
                ':new_action': [action_record],
                ':empty_list': []
            },
            ReturnValues='UPDATED_NEW'
        )
        
        return {
            'message': 'SOAR response processed successfully',
            'record': action_record
        }


    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'message': 'Internal Server Error'
        }