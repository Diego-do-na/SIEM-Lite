# Define the action weights for different AWS actions. These weights can be used to prioritize or score events based on their severity or importance.
ACTION_WEIGHTS = {
    'StopLogging': 400,
    'DeleteTrail': 400,
    'DisableKey': 400,
    'ScheduleKeyDeletion': 400,
    'UpdateTrail': 240,
    'DeleteSecurityGroup': 240,
    'AuthorizeSecurityGroupIngress': 200,
    'CreateSecurityGroup': 160,
    'RevokeSecurityGroupIngress': 120,
    'AuthorizeSecurityGroupEgress': 120,
    'RevokeSecurityGroupEgress': 80,
}

# Critical configuration events that are considered high-risk or sensitive. Only these contribute
# to globalCounts on the configChanges (Rule 1) branch, and they never feed the behavior baseline.
CRITICAL_CONFIG_EVENTS = {'StopLogging', 'DeleteTrail', 'DisableKey', 'ScheduleKeyDeletion'}


def get_severity(score):
    if score >= 600:
        return "CRITICAL"
    elif score >= 400:
        return "HIGH"
    elif score >= 200:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "NONE"
