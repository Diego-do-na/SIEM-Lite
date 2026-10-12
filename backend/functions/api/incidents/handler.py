import os
import logging

import boto3
from boto3.dynamodb.conditions import Key, Attr

from shared import api_utils as api

logger = logging.getLogger()
logger.setLevel(logging.INFO)

table = boto3.resource('dynamodb').Table(os.environ['INCIDENT_TABLE_NAME'])

DEFAULT_LIMIT = 50
MAX_LIMIT = 100
MAX_TEXT_LENGTH = 64
# A text search reads every incident in range and keeps the matches, so it is bounded
MAX_QUERY_PAGES = 50


def summarize(item):
    # The list leaves out the long Bedrock text and the per-action detail, the detail route has them
    return {
        'incidentId': item.get('incidentId'),
        'severity': item.get('severity'),
        'timestamp': item.get('timestamp'),
        'globalScore': item.get('globalScore'),
        'sourceIPAddress': item.get('sourceIPAddress'),
        'userIdentity': item.get('userIdentity'),
        'mitreTechniques': item.get('mitreTechniques', []),
        'duration': item.get('duration'),
        'responseTaken': len(item.get('defensiveActions') or []) > 0
    }


def text_param(params, name):
    value = (params.get(name) or '').strip()
    if len(value) > MAX_TEXT_LENGTH:
        raise ValueError(f"'{name}' is too long")
    return value


def time_condition(low, high):
    if low is not None and high is not None:
        return Key('timestamp').between(low, high)
    if low is not None:
        return Key('timestamp').gte(low)
    if high is not None:
        return Key('timestamp').lte(high)
    return None


def newest_matches(severity, low, high, filter_expression, limit):
    # Newest-first incidents of one severity that match, at most `limit`. Returns (items, may_have_more)
    condition = Key('severity').eq(severity)
    window = time_condition(low, high)
    if window is not None:
        condition = condition & window

    kwargs = {'KeyConditionExpression': condition, 'ScanIndexForward': False}
    if filter_expression is not None:
        kwargs['FilterExpression'] = filter_expression
    else:
        # Without a filter DynamoDB can stop exactly at the limit
        kwargs['Limit'] = limit

    items = []
    for _ in range(MAX_QUERY_PAGES):
        result = table.query(**kwargs)
        items.extend(result['Items'])
        if len(items) >= limit:
            return items[:limit], True
        if 'LastEvaluatedKey' not in result:
            return items, False
        kwargs['ExclusiveStartKey'] = result['LastEvaluatedKey']

    raise ValueError('the search is too broad, narrow the date range')


def list_incidents(params):
    severity = (params.get('severity') or '').upper()
    if severity and severity not in api.SEVERITIES:
        raise ValueError(f"'severity' must be one of {', '.join(api.SEVERITIES)}")
    severities = [severity] if severity else list(api.SEVERITIES)

    limit = api.int_param(params, 'limit', DEFAULT_LIMIT, 1, MAX_LIMIT)
    low = api.int_param(params, 'from', None, 0, 4102444800)
    high = api.int_param(params, 'to', None, 0, 4102444800)
    if low is not None and high is not None and low > high:
        raise ValueError("'from' must not be after 'to'")

    ip = text_param(params, 'ip')
    user = text_param(params, 'user')
    technique = text_param(params, 'technique')
    filter_expression = None
    for condition in (
        Attr('sourceIPAddress').begins_with(ip) if ip else None,
        Attr('userIdentity').contains(user) if user else None,
        Attr('mitreTechniques').contains(technique) if technique else None
    ):
        if condition is not None:
            filter_expression = condition if filter_expression is None else filter_expression & condition

    cursor = api.decode_cursor(params['cursor']) if params.get('cursor') else None

    candidates = []
    maybe_more = False
    for severity_name in severities:
        index = api.SEVERITIES.index(severity_name)
        upper = high
        if cursor:
            cursor_ts, cursor_index = cursor
            # Ties on the timestamp are ordered by severity, so this severity continues at the same second
            # only if it comes after the one of the cursor
            cap = cursor_ts if index > cursor_index else cursor_ts - 1
            upper = cap if upper is None else min(upper, cap)
        if upper is not None and upper < 0:
            continue

        found, more = newest_matches(severity_name, low, upper, filter_expression, limit)
        maybe_more = maybe_more or more
        candidates.extend((item, index) for item in found)

    candidates.sort(key=lambda pair: (-int(pair[0]['timestamp']), pair[1]))
    page = candidates[:limit]
    has_more = maybe_more or len(candidates) > limit

    next_cursor = None
    if page and has_more:
        last_item, last_index = page[-1]
        next_cursor = api.encode_cursor(last_item['timestamp'], last_index)

    return api.response(200, {'items': [summarize(item) for item, _ in page], 'nextCursor': next_cursor})


def get_incident(path_params):
    severity = (path_params.get('severity') or '').upper()
    if severity not in api.SEVERITIES:
        raise ValueError(f"'severity' must be one of {', '.join(api.SEVERITIES)}")

    try:
        timestamp = int(path_params.get('timestamp', ''))
    except ValueError:
        raise ValueError("'timestamp' must be an integer")

    result = table.get_item(Key={'severity': severity, 'timestamp': timestamp})
    if 'Item' not in result:
        return api.error(404, 'incident not found')
    return api.response(200, result['Item'])


def lambda_handler(event, context):
    route = event.get('routeKey', '')
    params = event.get('queryStringParameters') or {}
    path_params = event.get('pathParameters') or {}

    try:
        if route == 'GET /incidents':
            return list_incidents(params)
        if route == 'GET /incidents/{severity}/{timestamp}':
            return get_incident(path_params)
        return api.error(404, 'route not found')
    except ValueError as e:
        return api.error(400, str(e))
    except Exception:
        logger.exception(f"Error handling {route}")
        return api.server_error(context)
