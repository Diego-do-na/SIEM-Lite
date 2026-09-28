from shared.scoring import ACTION_WEIGHTS, CRITICAL_CONFIG_EVENTS

MITRE_MAP = {
    'StopLogging': 'T1562.008',
    'DeleteTrail': 'T1562.008',
    'UpdateTrail': 'T1562.008',
    'AuthorizeSecurityGroupIngress': 'T1562.007',
    'AuthorizeSecurityGroupEgress': 'T1562.007',
    'RevokeSecurityGroupIngress': 'T1562.007',
    'RevokeSecurityGroupEgress': 'T1562.007',
    'CreateSecurityGroup': 'T1562.007',
    'DeleteSecurityGroup': 'T1562.007',
    'DisableKey': 'T1485',
    'ScheduleKeyDeletion': 'T1485',
}


def get_mitre_techniques(item):
    """Collect unique MITRE techniques from every action seen in this incident."""
    techniques = set()

    for action_name in item.get('actionCounts', {}).keys():
        technique = MITRE_MAP.get(action_name)
        if technique:
            techniques.add(technique)
        else:
            # Denied-access actions not in the static map get a generic
            # brute-force/discovery technique when repeated.
            techniques.add('T1110')

    for action_name in item.get('configChanges', {}).keys():
        technique = MITRE_MAP.get(action_name)
        if technique:
            techniques.add(technique)

    return sorted(techniques)


def get_action_score_breakdown(item):
    """Build a flat {action_name: score} breakdown from what siem_lite_detection
    actually wrote. Prefers the stored 'score' (the real increment applied,
    already scaled by the Rule 3 behavior multiplier when active). Falls back
    to weight * count for items written before 'score' existed, or for
    non-critical configChanges entries that never had a score to begin with.
    """
    breakdown = {}

    for action_name, details in item.get('actionCounts', {}).items():
        if 'score' in details:
            breakdown[action_name] = int(details['score'])
        else:
            count = int(details.get('count', 0))
            weight = ACTION_WEIGHTS.get(action_name, 40)
            breakdown[action_name] = weight * count

    for action_name, details in item.get('configChanges', {}).items():
        if action_name in CRITICAL_CONFIG_EVENTS:
            if 'score' in details:
                breakdown[action_name] = int(details['score'])
            else:
                count = int(details.get('count', 0))
                weight = ACTION_WEIGHTS.get(action_name, 0)
                breakdown[action_name] = weight * count

    return breakdown
