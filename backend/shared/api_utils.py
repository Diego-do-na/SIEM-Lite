import json
import base64
from decimal import Decimal

from boto3.dynamodb.conditions import Key

# Severities that are stored and shown. NONE exists in scoring but carries no signal for a dashboard
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _json_default(value):
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def response(status, body):
    # CORS is handled by API Gateway itself, so no CORS headers here
    return {
        'statusCode': status,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps(body, default=_json_default)
    }


def error(status, message):
    return response(status, {'error': message})


def server_error(context):
    # The traceback is in CloudWatch under this request id, the caller only gets the id
    return response(500, {'error': 'internal error', 'requestId': getattr(context, 'aws_request_id', None)})


def get_groups(event):
    # HTTP API turns the cognito:groups array into a string like "[admin viewer]"
    claims = event.get('requestContext', {}).get('authorizer', {}).get('jwt', {}).get('claims', {})
    raw = claims.get('cognito:groups', '')
    if isinstance(raw, list):
        return raw
    return [g for g in raw.strip('[]').replace(',', ' ').split() if g]


def int_param(params, name, default, minimum, maximum):
    raw = params.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"'{name}' must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"'{name}' must be between {minimum} and {maximum}")
    return value


def encode_cursor(timestamp, severity_index):
    # Position of the last item returned: incidents are ordered by timestamp (newest first), then by severity order
    return base64.urlsafe_b64encode(json.dumps({'t': int(timestamp), 's': severity_index}).encode()).decode()


def decode_cursor(cursor):
    try:
        key = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        timestamp, severity_index = key['t'], key['s']
        if not isinstance(timestamp, int) or not isinstance(severity_index, int):
            raise ValueError
        if timestamp < 0 or severity_index < 0 or severity_index >= len(SEVERITIES):
            raise ValueError
        return timestamp, severity_index
    except Exception:
        raise ValueError("invalid cursor")


def is_cache_valid(cached, version, now, max_age, min_age=60):
    # Served while no incident arrived since it was computed, but never older than max_age:
    # time windows like "last 24 hours" slide even when nothing new happens.
    # min_age is a floor between two recomputations, even during a burst of incidents
    age = now - int(cached['createdAt'])
    if age < min_age:
        return True
    return int(cached['version']) == version and age < max_age


def last_incident_at(table):
    # Newest incident across all severities; it doubles as the version of the data for the cache
    newest = 0
    for severity in SEVERITIES:
        result = table.query(
            KeyConditionExpression=Key('severity').eq(severity),
            ScanIndexForward=False,
            Limit=1
        )
        if result['Items']:
            newest = max(newest, int(result['Items'][0]['timestamp']))
    return newest


def count_incidents(table, severity, since=None):
    condition = Key('severity').eq(severity)
    if since is not None:
        condition = condition & Key('timestamp').gte(since)

    total = 0
    kwargs = {'KeyConditionExpression': condition, 'Select': 'COUNT'}
    while True:
        result = table.query(**kwargs)
        total += result['Count']
        if 'LastEvaluatedKey' not in result:
            return total
        kwargs['ExclusiveStartKey'] = result['LastEvaluatedKey']
