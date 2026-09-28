import os
import math
import ipaddress
from datetime import datetime, timezone

# Rule 3: pure math of the behavior multiplier (time of day + source IP). No AWS calls here.
# Tunables are read from the same env vars as before, with the same defaults.
Z_LOW = float(os.environ.get('BASELINE_Z_LOW', '1.0'))             # z clearly normal (s = -1)
Z_HIGH = float(os.environ.get('BASELINE_Z_HIGH', '3.0'))           # z clearly anomalous (s = +1)
IP_BUMP_SAME_RANGE = float(os.environ.get('BASELINE_IP_BUMP_SAME_RANGE', '0.25'))  # new IP, known range
IP_BUMP_NEW_RANGE = float(os.environ.get('BASELINE_IP_BUMP_NEW_RANGE', '0.75'))    # IP in a never-seen range
SIGMA_MIN_RAD = 2 * math.pi / 24                                   # sigma floor: 1 hour


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


def time_signal(hour_record, event_time):
    # Signal s in [-1, +1]: negative = within normal pattern, positive = outside it
    n = float(hour_record.get('eventCount', 0))
    if n <= 0:
        return 0.0

    s_sum = float(hour_record.get('hourSinSum', 0))
    c_sum = float(hour_record.get('hourCosSum', 0))

    # Mean resultant length R (0 = scattered hours, 1 = always the same hour)
    r = math.sqrt(s_sum ** 2 + c_sum ** 2) / n
    r = min(max(r, 0.05), 1.0)

    mean_angle = math.atan2(s_sum, c_sum)
    sigma = max(math.sqrt(-2 * math.log(r)), SIGMA_MIN_RAD)

    dt = parse_event_time(event_time)
    theta = 2 * math.pi * (dt.hour + dt.minute / 60) / 24

    # Circular angular distance in [0, pi]
    distance = abs((theta - mean_angle + math.pi) % (2 * math.pi) - math.pi)
    z = distance / sigma

    neutral = (Z_LOW + Z_HIGH) / 2
    half_width = (Z_HIGH - Z_LOW) / 2
    return max(-1.0, min(1.0, (z - neutral) / half_width))


def ip_bump(items, source_ip):
    # 0 if known, small if new IP in a known range, large if the range is new
    ip = normalize_ip(source_ip)
    if not ip:
        return 0.0  # AWS service callers: no signal

    known = []
    for item in items:
        record_type = item.get('recordType', '')
        if record_type.startswith('IP#'):
            known.append(record_type[3:])

    if ip in known:
        return 0.0

    ip_obj = ipaddress.ip_address(ip)
    prefix = 24 if ip_obj.version == 4 else 48
    network = ipaddress.ip_network(f'{ip}/{prefix}', strict=False)
    for known_ip in known:
        try:
            if ipaddress.ip_address(known_ip) in network:
                return IP_BUMP_SAME_RANGE
        except ValueError:
            continue
    return IP_BUMP_NEW_RANGE


def apply_multiplier(weight, multiplier):
    # boto3 resource rejects floats: always an int, minimum 1
    return max(1, int(round(weight * multiplier)))
