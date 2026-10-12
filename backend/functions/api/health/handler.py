import time

from shared import api_utils as api


def lambda_handler(event, context):
    # Public liveness check: it touches nothing else on purpose
    return api.response(200, {'status': 'ok', 'time': int(time.time())})
