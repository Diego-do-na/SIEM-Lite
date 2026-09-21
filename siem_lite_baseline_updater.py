import os
import math
import time
import logging
import ipaddress
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['BASELINE_TABLE_NAME'])

IP_TTL_DAYS = int(os.environ.get('IP_TTL_DAYS', '30'))

# Critical events never feed the baseline (anti-poisoning); the EventBridge rule also excludes them
CRITICAL_CONFIG_EVENTS = {'StopLogging', 'DeleteTrail', 'DisableKey', 'ScheduleKeyDeletion'}

# Per-container caches to skip repeated writes; the ConditionExpressions keep it correct on cold starts
_last_hour_bucket = {}
_last_day = {}
_last_ip_bucket = {}
CACHE_MAX_ENTRIES = 2000


def get_principal_key(user_identity):
    # Users only: roles and services get no baseline
    if user_identity.get('type') in ('IAMUser', 'Root'):
        return user_identity.get('arn')
    return None


def normalize_ip(raw):
    # Returns None for non-IP sources (e.g. AWS service names)
    try:
        return str(ipaddress.ip_address(raw))
    except (ValueError, TypeError):
        return None


def parse_event_time(value):
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def to_decimal(x):
    return Decimal(f"{x:.8f}")


def is_conditional_failure(error):
    return error.response.get('Error', {}).get('Code') == 'ConditionalCheckFailedException'


def cap_cache(cache):
    if len(cache) > CACHE_MAX_ENTRIES:
        cache.clear()


def write_day(principal, day):
    # Counts distinct active days without storing the dates
    try:
        table.update_item(
            Key={'userIdentity': principal, 'recordType': 'HOUR'},
            UpdateExpression='SET lastDayCounted = :d ADD daysSeen :one',
            ConditionExpression='attribute_not_exists(lastDayCounted) OR lastDayCounted <> :d',
            ExpressionAttributeValues={':d': day, ':one': 1}
        )
    except ClientError as e:
        if not is_conditional_failure(e):
            raise


def write_hour_vote(principal, dt, bucket):
    # One vote per active hour: adds sin/cos of the event hour (UTC)
    theta = 2 * math.pi * (dt.hour + dt.minute / 60) / 24
    now = int(dt.timestamp())
    try:
        table.update_item(
            Key={'userIdentity': principal, 'recordType': 'HOUR'},
            UpdateExpression=(
                'SET lastBucket = :b, lastUpdated = :now, '
                'firstUpdated = if_not_exists(firstUpdated, :now) '
                'ADD hourSinSum :s, hourCosSum :c, eventCount :one'
            ),
            ConditionExpression='attribute_not_exists(lastBucket) OR lastBucket <> :b',
            ExpressionAttributeValues={
                ':b': bucket,
                ':now': now,
                ':s': to_decimal(math.sin(theta)),
                ':c': to_decimal(math.cos(theta)),
                ':one': 1
            }
        )
    except ClientError as e:
        if not is_conditional_failure(e):
            raise


def write_ip(principal, ip, bucket):
    # One record per IP, counted once per hour; TTL renewed on each sighting
    now = int(time.time())
    try:
        table.update_item(
            Key={'userIdentity': principal, 'recordType': f'IP#{ip}'},
            UpdateExpression='SET lastBucket = :b, lastSeen = :now, #ttl = :ttl ADD #c :one',
            ConditionExpression='attribute_not_exists(lastBucket) OR lastBucket <> :b',
            ExpressionAttributeNames={'#ttl': 'ttl', '#c': 'count'},
            ExpressionAttributeValues={
                ':b': bucket,
                ':now': now,
                ':ttl': now + IP_TTL_DAYS * 86400,
                ':one': 1
            }
        )
    except ClientError as e:
        if not is_conditional_failure(e):
            raise


def lambda_handler(event, context):
    try:
        detail = event['detail']

        # Valid activity only
        if 'errorCode' in detail or detail.get('eventName') in CRITICAL_CONFIG_EVENTS:
            return

        principal = get_principal_key(detail.get('userIdentity', {}))
        if not principal:
            return

        dt = parse_event_time(detail.get('eventTime') or event.get('time'))
        bucket = dt.strftime('%Y-%m-%dT%H')
        day = dt.strftime('%Y-%m-%d')

        if _last_day.get(principal) != day:
            write_day(principal, day)
            _last_day[principal] = day
            cap_cache(_last_day)

        if _last_hour_bucket.get(principal) != bucket:
            write_hour_vote(principal, dt, bucket)
            _last_hour_bucket[principal] = bucket
            cap_cache(_last_hour_bucket)

        ip = normalize_ip(detail.get('sourceIPAddress'))
        if ip and _last_ip_bucket.get((principal, ip)) != bucket:
            write_ip(principal, ip, bucket)
            _last_ip_bucket[(principal, ip)] = bucket
            cap_cache(_last_ip_bucket)

        logger.info("Baseline update completed")

    except Exception as e:
        # Sanitized log; errors are swallowed to avoid EventBridge retries
        code = e.response.get('Error', {}).get('Code') if isinstance(e, ClientError) else type(e).__name__
        logger.error(f"Baseline update failed: {code}")