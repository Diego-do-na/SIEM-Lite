import os
import json
import time
import logging
from decimal import Decimal
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.types import TypeDeserializer

deserializer = TypeDeserializer()
s3 = boto3.client('s3')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RAW_BUCKET = os.environ.get('RAW_BUCKET_NAME')
PROCESSED_BUCKET = os.environ.get('PROCESSED_BUCKET_NAME')

# Everything under this prefix is the Athena table (partitioned as day=YYYY-MM-DD); the table location and the
# partition projection template in Terraform must match it
PROCESSED_PREFIX = 'incidents'

def deserialize_item(dynamodb_json):
    return {k: deserializer.deserialize(v) for k, v in dynamodb_json.items()}

def json_default(value):
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")

def total_count(counters):
    # actionCounts / configChanges map an action name to {"count": n, ...}
    return sum(int(details.get('count', 0)) for details in counters.values() if isinstance(details, dict))

def curate(item, incident_timestamp):
    # Flat, typed row for Athena. Keys are lowercase to match the table columns.
    # The original event stays untouched in the raw bucket
    action_counts = item.get('actionCounts') or {}
    config_changes = item.get('configChanges') or {}
    defensive_actions = item.get('defensiveActions') or []
    dt = datetime.fromtimestamp(incident_timestamp, tz=timezone.utc)

    return {
        'incidentid': item.get('incidentId'),
        'severity': item.get('severity'),
        'globalscore': int(item.get('globalScore', 0)),
        'useridentity': item.get('userIdentity'),
        'sourceipaddress': item.get('sourceIPAddress'),
        'timestamp': incident_timestamp,
        'firstseen': int(item.get('firstSeen', 0)),
        'lastseen': int(item.get('lastSeen', 0)),
        'duration': int(item.get('duration', 0)),
        'mitretechniques': list(item.get('mitreTechniques') or []),
        'actionnames': sorted(set(action_counts) | set(config_changes)),
        'eventcount': total_count(action_counts) + total_count(config_changes),
        'responsetaken': len(defensive_actions) > 0,
        'responsesucceeded': any(a.get('success') for a in defensive_actions),
        'hourutc': dt.hour
    }

def lambda_handler(event, context):
    for record in event['Records']:
        try:
            if record.get('eventName') != 'INSERT':
                continue

            new_image = record['dynamodb']['NewImage']
            item = deserialize_item(new_image)

            incident_id = item.get('incidentId')
            incident_timestamp = int(item.get('timestamp', int(time.time())))
            dt = datetime.fromtimestamp(incident_timestamp, tz=timezone.utc)
            partition = f"year={dt.year:04d}/month={dt.month:02d}/day={dt.day:02d}"

            raw_key = f"{partition}/{incident_id}.json"
            s3.put_object(
                Bucket=RAW_BUCKET,
                Key=raw_key,
                Body=json.dumps(item, default=json_default),
                ContentType='application/json'
            )
            logger.info(f"Incident exported to raw: s3://{RAW_BUCKET}/{raw_key}")

            # One JSON line per file; the object key is the incident id, so a retry overwrites instead of duplicating
            processed_key = f"{PROCESSED_PREFIX}/day={dt:%Y-%m-%d}/{incident_id}.json"
            s3.put_object(
                Bucket=PROCESSED_BUCKET,
                Key=processed_key,
                Body=json.dumps(curate(item, incident_timestamp), default=json_default) + '\n',
                ContentType='application/json'
            )
            logger.info(f"Incident exported to processed: s3://{PROCESSED_BUCKET}/{processed_key}")
        except Exception as e:
            logger.error(f"Error exporting record: {str(e)}")
