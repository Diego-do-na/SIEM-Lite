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

def deserialize_item(dynamodb_json):
    return {k: deserializer.deserialize(v) for k, v in dynamodb_json.items()}

def json_default(value):
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")

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

            key = f"year={dt.year:04d}/month={dt.month:02d}/day={dt.day:02d}/{incident_id}.json"

            s3.put_object(
                Bucket=RAW_BUCKET,
                Key=key,
                Body=json.dumps(item, default=json_default),
                ContentType='application/json'
            )

            logger.info(f"Incident exported to raw: s3://{RAW_BUCKET}/{key}")
        except Exception as e:
            logger.error(f"Error exporting record: {str(e)}")
