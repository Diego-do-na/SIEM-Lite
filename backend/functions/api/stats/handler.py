import os
import json
import time
import logging

import boto3

from shared import api_utils as api

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['INCIDENT_TABLE_NAME'])
cache_table = dynamodb.Table(os.environ['CACHE_TABLE_NAME'])

WINDOWS = {'24h': 24 * 3600, '7d': 7 * 24 * 3600, 'all': None}

CACHE_KEY = 'stats'
# The 24h and 7d windows slide with time, so the counts are recomputed at least this often
CACHE_MAX_AGE_SECONDS = 300
CACHE_MIN_AGE_SECONDS = 60
CACHE_TTL_SECONDS = 24 * 3600


def counts_since(since):
    counts = {severity: api.count_incidents(table, severity, since) for severity in api.SEVERITIES}
    counts['total'] = sum(counts.values())
    return counts


def compute_windows(now):
    return {
        name: counts_since(None if seconds is None else now - seconds)
        for name, seconds in WINDOWS.items()
    }


def lambda_handler(event, context):
    try:
        now = int(time.time())
        # Cheap (one item per severity). The dashboard polls this value to know when something new arrived
        version = api.last_incident_at(table)

        cached = cache_table.get_item(Key={'cacheKey': CACHE_KEY}).get('Item')
        if cached and api.is_cache_valid(cached, version, now, CACHE_MAX_AGE_SECONDS, CACHE_MIN_AGE_SECONDS):
            stored = json.loads(cached['payload'])
            windows, generated_at, from_cache = stored['windows'], stored['generatedAt'], True
        else:
            windows, generated_at, from_cache = compute_windows(now), now, False
            cache_table.put_item(Item={
                'cacheKey': CACHE_KEY,
                'version': version,
                'createdAt': now,
                'payload': json.dumps({'windows': windows, 'generatedAt': now}),
                'ttl': now + CACHE_TTL_SECONDS
            })

        return api.response(200, {
            'generatedAt': generated_at,
            'lastIncidentAt': version,
            'cached': from_cache,
            'windows': windows
        })
    except Exception:
        logger.exception("Error computing stats")
        return api.server_error(context)
