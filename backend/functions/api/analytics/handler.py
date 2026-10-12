import os
import json
import time
import logging
from datetime import datetime, timezone
from collections import OrderedDict

import boto3

from shared import api_utils as api

logger = logging.getLogger()
logger.setLevel(logging.INFO)

athena = boto3.client('athena')
incident_table = boto3.resource('dynamodb').Table(os.environ['INCIDENT_TABLE_NAME'])
cache_table = boto3.resource('dynamodb').Table(os.environ['CACHE_TABLE_NAME'])

ATHENA_DATABASE = os.environ['ATHENA_DATABASE']
ATHENA_TABLE = os.environ['ATHENA_TABLE']
ATHENA_WORKGROUP = os.environ['ATHENA_WORKGROUP']

ALLOWED_DAYS = (7, 30, 90)
DEFAULT_DAYS = 30
POLL_INTERVAL_SECONDS = 0.5
MAX_POLL_ATTEMPTS = 50  # ~25s, under the 29s timeout of the function

# A cached answer is served while no new incident arrived, but never for longer than this:
# the "last N days" window slides even when nothing new happens
CACHE_MAX_AGE_SECONDS = 6 * 3600
# Floor between two Athena runs of the same report, even during a burst of incidents
CACHE_MIN_AGE_SECONDS = 60
CACHE_TTL_SECONDS = 7 * 24 * 3600


def build_query(report, since):
    # Only 'since' (integer) and the date derived from it are interpolated, both computed here: nothing from the request reaches the SQL text
    # `day` is the partition column: filtering on it makes Athena list only those days in S3
    day = datetime.fromtimestamp(since, tz=timezone.utc).strftime('%Y-%m-%d')
    base = f"FROM {ATHENA_TABLE} WHERE day >= '{day}' AND \"timestamp\" >= {since}"

    queries = {
        'top-ips': (
            f'SELECT sourceipaddress AS ip, count(*) AS incidents, max(globalscore) AS max_score '
            f'{base} AND sourceipaddress IS NOT NULL GROUP BY 1 ORDER BY incidents DESC, max_score DESC LIMIT 10'
        ),
        'mitre-techniques': (
            f'SELECT technique, count(*) AS incidents '
            f'FROM {ATHENA_TABLE} CROSS JOIN UNNEST(mitretechniques) AS t(technique) '
            f"WHERE day >= '{day}' AND \"timestamp\" >= {since} GROUP BY 1 ORDER BY incidents DESC LIMIT 10"
        ),
        'severity-trend': (
            f'SELECT cast(date(from_unixtime("timestamp")) AS varchar) AS dt, severity, count(*) AS incidents '
            f'{base} GROUP BY 1, 2 ORDER BY 1'
        ),
        'score-distribution': (
            f'SELECT cast(floor(globalscore / 100) * 100 AS integer) AS bucket_start, count(*) AS incidents '
            f'{base} GROUP BY 1 ORDER BY 1'
        )
    }
    return queries[report]


def shape(report, rows):
    # Athena returns every value as a string
    if report == 'top-ips':
        return [{'ip': r['ip'], 'incidents': int(r['incidents']), 'maxScore': int(r['max_score'])} for r in rows]
    if report == 'mitre-techniques':
        return [{'technique': r['technique'], 'incidents': int(r['incidents'])} for r in rows]
    if report == 'severity-trend':
        days = OrderedDict()
        for r in rows:
            day = days.setdefault(r['dt'], {'day': r['dt'], **{s: 0 for s in api.SEVERITIES}})
            if r['severity'] in day:
                day[r['severity']] = int(r['incidents'])
        return list(days.values())
    return [
        {'bucket': f"{int(r['bucket_start'])}-{int(r['bucket_start']) + 99}", 'incidents': int(r['incidents'])}
        for r in rows
    ]


def run_athena_query(query):
    execution = athena.start_query_execution(
        QueryString=query,
        WorkGroup=ATHENA_WORKGROUP,
        QueryExecutionContext={'Database': ATHENA_DATABASE}
    )
    execution_id = execution['QueryExecutionId']

    for _ in range(MAX_POLL_ATTEMPTS):
        state = athena.get_query_execution(QueryExecutionId=execution_id)['QueryExecution']['Status']
        if state['State'] == 'SUCCEEDED':
            return get_rows(execution_id)
        if state['State'] in ('FAILED', 'CANCELLED'):
            raise RuntimeError(f"Athena query {state['State']}: {state.get('StateChangeReason', 'unknown')}")
        time.sleep(POLL_INTERVAL_SECONDS)

    # Do not leave it running (and billing) after the caller gave up
    try:
        athena.stop_query_execution(QueryExecutionId=execution_id)
    except Exception:
        logger.warning(f"Could not stop Athena query {execution_id}")
    raise TimeoutError('Athena query did not complete in time')


def get_rows(execution_id):
    rows = []
    for page in athena.get_paginator('get_query_results').paginate(QueryExecutionId=execution_id):
        for row in page['ResultSet']['Rows']:
            rows.append([col.get('VarCharValue', '') for col in row['Data']])

    if not rows:
        return []
    header = rows[0]
    return [dict(zip(header, row)) for row in rows[1:]]


def lambda_handler(event, context):
    report = (event.get('pathParameters') or {}).get('report', '')
    params = event.get('queryStringParameters') or {}

    if report not in ('top-ips', 'mitre-techniques', 'severity-trend', 'score-distribution'):
        return api.error(404, 'unknown report')

    try:
        days = api.int_param(params, 'days', DEFAULT_DAYS, 1, 365)
        if days not in ALLOWED_DAYS:
            raise ValueError(f"'days' must be one of {', '.join(str(d) for d in ALLOWED_DAYS)}")

        now = int(time.time())
        version = api.last_incident_at(incident_table)
        cache_key = f"{report}#{days}"

        cached = cache_table.get_item(Key={'cacheKey': cache_key}).get('Item')
        if cached and api.is_cache_valid(cached, version, now, CACHE_MAX_AGE_SECONDS, CACHE_MIN_AGE_SECONDS):
            body = json.loads(cached['payload'])
            body['cached'] = True
            return api.response(200, body)

        data = shape(report, run_athena_query(build_query(report, now - days * 24 * 3600)))
        body = {'report': report, 'days': days, 'generatedAt': now, 'version': version, 'cached': False, 'data': data}

        cache_table.put_item(Item={
            'cacheKey': cache_key,
            'version': version,
            'createdAt': now,
            'payload': json.dumps(body),
            'ttl': now + CACHE_TTL_SECONDS
        })
        return api.response(200, body)
    except ValueError as e:
        return api.error(400, str(e))
    except TimeoutError:
        return api.error(504, 'the analytics query took too long, try again')
    except Exception:
        logger.exception(f"Error running report {report}")
        return api.server_error(context)
