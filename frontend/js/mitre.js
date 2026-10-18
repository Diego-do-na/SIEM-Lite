// What SIEM Lite knows about MITRE ATT&CK. It mirrors backend/shared/mitre.py (MITRE_MAP), backend/shared/scoring.py
// (ACTION_WEIGHTS) and the SOAR Lambda, so the dictionary describes what the system really does and nothing more.
// Pure data, no DOM. If a rule is added in the backend, add it here too.

// Tactics of the ATT&CK matrix for IaaS (cloud), in matrix order
export const TACTICS = [
    { id: "TA0001", name: "Initial Access" },
    { id: "TA0002", name: "Execution" },
    { id: "TA0003", name: "Persistence" },
    { id: "TA0004", name: "Privilege Escalation" },
    { id: "TA0005", name: "Defense Evasion" },
    { id: "TA0006", name: "Credential Access" },
    { id: "TA0007", name: "Discovery" },
    { id: "TA0008", name: "Lateral Movement" },
    { id: "TA0009", name: "Collection" },
    { id: "TA0010", name: "Exfiltration" },
    { id: "TA0040", name: "Impact" }
];

export const TECHNIQUES = {
    "T1562.008": {
        id: "T1562.008", name: "Disable or Modify Cloud Logs", tactic: "Defense Evasion", parent: "Impair Defenses",
        url: "https://attack.mitre.org/techniques/T1562/008/",
        summary: "An attacker who has cloud credentials turns off or alters the audit trail so that what they do next leaves no record. In AWS this means stopping, deleting or reconfiguring CloudTrail.",
        events: ["StopLogging", "DeleteTrail", "UpdateTrail"],
        detection: "Any of these three CloudTrail calls raises the incident. StopLogging and DeleteTrail weigh 400 points each, which alone reaches High; UpdateTrail weighs 240.",
        response: "Automatic. StopLogging: the trail is started again. DeleteTrail: the trail is recreated from its last configuration kept by AWS Config and logging is verified. UpdateTrail: alert only.",
        mitigations: [
            "Deny cloudtrail:StopLogging, DeleteTrail and UpdateTrail to everyone except a break-glass role (IAM policy or an SCP).",
            "Enable log file validation and send logs to a bucket the workload account cannot modify (separate account, Object Lock).",
            "Use a multi-region trail so a region cannot be used to hide activity."
        ]
    },
    "T1562.007": {
        id: "T1562.007", name: "Disable or Modify Cloud Firewall", tactic: "Defense Evasion", parent: "Impair Defenses",
        url: "https://attack.mitre.org/techniques/T1562/007/",
        summary: "Network controls are loosened so an attacker can reach resources or move data out. In AWS the usual target is a security group: opening a port to the internet, adding an egress path, or deleting a group that blocks traffic.",
        events: ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"],
        detection: "Security group changes add points per call: DeleteSecurityGroup 240, AuthorizeSecurityGroupIngress 200, CreateSecurityGroup 160, Authorize/Revoke egress and Revoke ingress 80 to 120. A single change is Low or Medium; a burst of them climbs.",
        response: "Alert only. There is no automatic undo, because reverting a firewall rule without context could break a legitimate change.",
        mitigations: [
            "Limit ec2:AuthorizeSecurityGroup* and ec2:DeleteSecurityGroup to a network administration role.",
            "Turn on AWS Config rules that flag security groups open to 0.0.0.0/0 on sensitive ports.",
            "Review changes against a ticket: an unexpected change from a service user is the signal."
        ]
    },
    "T1485": {
        id: "T1485", name: "Data Destruction", tactic: "Impact", parent: null,
        url: "https://attack.mitre.org/techniques/T1485/",
        summary: "Data is made unrecoverable to interrupt a business or cover tracks. In AWS, disabling or scheduling the deletion of a KMS key does it indirectly: everything encrypted with that key becomes unreadable.",
        events: ["DisableKey", "ScheduleKeyDeletion"],
        detection: "Both KMS calls weigh 400 points, so one of them reaches High on its own and together with another critical action it reaches Critical.",
        response: "Automatic. DisableKey: the key is enabled again. ScheduleKeyDeletion: the deletion is cancelled. The result is stored with the incident.",
        mitigations: [
            "Restrict kms:DisableKey and kms:ScheduleKeyDeletion in the key policy to a small administrative role.",
            "Keep the deletion window at its maximum (30 days) so a mistake or an attack can still be reversed.",
            "Alert on both events and require a second person for key administration."
        ]
    },
    "T1110": {
        id: "T1110", name: "Brute Force", tactic: "Credential Access", parent: null,
        url: "https://attack.mitre.org/techniques/T1110/",
        summary: "Repeated attempts to gain access: guessing passwords, trying many credentials or probing which actions an identity is allowed to perform.",
        events: ["Any API call that is denied and is not in the table above"],
        detection: "This is a generic label. The detection rules attach it to repeated denied-access activity that does not match a more specific technique, each call adding a small base weight. It is a signal worth reviewing, not proof of password guessing.",
        response: "Alert only.",
        mitigations: [
            "Require MFA for console users and remove access keys that are not in use.",
            "Apply least privilege so a stolen identity gets denied quickly, and alert on bursts of AccessDenied.",
            "Check the source IP and the user: an internal service user suddenly failing from a new address is the usual pattern."
        ]
    }
};

// Every action the detection scores, with what it means and whether SOAR answers it
export const ACTIONS = {
    StopLogging: { weight: 400, technique: "T1562.008", what: "CloudTrail logging was switched off for a trail.", soar: "Logging started again" },
    DeleteTrail: { weight: 400, technique: "T1562.008", what: "A CloudTrail trail was deleted.", soar: "Trail recreated from AWS Config and verified" },
    UpdateTrail: { weight: 240, technique: "T1562.008", what: "A trail's settings were changed (bucket, regions, validation).", soar: null },
    DisableKey: { weight: 400, technique: "T1485", what: "A KMS key was disabled; data encrypted with it cannot be read.", soar: "Key enabled again" },
    ScheduleKeyDeletion: { weight: 400, technique: "T1485", what: "A KMS key was scheduled for deletion.", soar: "Deletion cancelled" },
    DeleteSecurityGroup: { weight: 240, technique: "T1562.007", what: "A security group was deleted.", soar: null },
    AuthorizeSecurityGroupIngress: { weight: 200, technique: "T1562.007", what: "An inbound rule was added to a security group.", soar: null },
    CreateSecurityGroup: { weight: 160, technique: "T1562.007", what: "A new security group was created.", soar: null },
    RevokeSecurityGroupIngress: { weight: 120, technique: "T1562.007", what: "An inbound rule was removed from a security group.", soar: null },
    AuthorizeSecurityGroupEgress: { weight: 120, technique: "T1562.007", what: "An outbound rule was added to a security group.", soar: null },
    RevokeSecurityGroupEgress: { weight: 80, technique: "T1562.007", what: "An outbound rule was removed from a security group.", soar: null }
};

export const techniqueName = (id) => (TECHNIQUES[id] ? TECHNIQUES[id].name : "");
export const tacticOf = (id) => (TECHNIQUES[id] ? TECHNIQUES[id].tactic : "Other");
export const actionInfo = (name) => ACTIONS[name] || { weight: 40, technique: "T1110", what: "An API call that was denied or not recognised by the rules.", soar: null };
