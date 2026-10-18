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

// Descriptions are written from the ATT&CK pages (attack.mitre.org), shortened and adapted to AWS. Procedure examples and
// mitigation ids are the ones MITRE lists for each technique.
export const MITRE_NOTICE = "Technique descriptions adapted from MITRE ATT&CK®, © The MITRE Corporation, used under the ATT&CK Terms of Use.";

export const TECHNIQUES = {
    "T1562.008": {
        id: "T1562.008", name: "Disable or Modify Cloud Logs", tactic: "Defense Evasion", parent: "Impair Defenses",
        url: "https://attack.mitre.org/techniques/T1562/008/",
        summary: "An attacker with cloud credentials turns off or alters the audit trail so that what they do next leaves no record.",
        about: [
            "Adversaries disable or modify cloud logging to limit what is recorded about their activity. Cloud platforms keep an audit log of every API call, so an attacker with enough permissions can switch that record off, redirect it somewhere they control, or weaken the settings that make it trustworthy.",
            "Typical moves are stopping or deleting a trail, changing where logs are delivered, turning off log file validation or encryption, and limiting logging to a single region so that activity elsewhere goes unseen. Everything that follows becomes harder to reconstruct, so this often comes early in an intrusion, before the actions the attacker really wants to hide."
        ],
        inAws: "CloudTrail is the main target. StopLogging pauses a trail, DeleteTrail removes it, and UpdateTrail can change its bucket, its regions or its validation settings. A trail that stops logging produces no new records, so the StopLogging call can be the last event you ever see from that moment on. That is why SIEM Lite answers it automatically within seconds.",
        events: ["StopLogging", "DeleteTrail", "UpdateTrail"],
        examples: [
            { name: "Offensive AWS frameworks", text: "Tools such as Pacu include modules aimed at disrupting detection services like CloudTrail once an account is compromised, which makes this a standard step in cloud attack playbooks." }
        ],
        detection: "Any of these three CloudTrail calls raises the incident. StopLogging and DeleteTrail weigh 400 points each, which alone reaches High; UpdateTrail weighs 240.",
        response: "Automatic. StopLogging: the trail is started again. DeleteTrail: the trail is recreated from its last configuration kept by AWS Config and logging is verified. UpdateTrail: alert only.",
        investigate: [
            "Who made the call: a person, a pipeline role or a service? Check whether that identity normally touches CloudTrail at all.",
            "Source IP and region: an address or a region that this account never uses is a strong signal.",
            "What happened around it: look at IAM, KMS and security group calls in the minutes before and after.",
            "Confirm the trail is logging again and that its bucket, regions and log file validation still have their expected settings."
        ],
        benign: [
            "A planned migration of trails or log buckets by the platform team.",
            "Infrastructure as code (Terraform) recreating a trail during an apply: look for the pipeline role and a matching change record."
        ],
        mitigations: [
            { text: "Deny cloudtrail:StopLogging, DeleteTrail and UpdateTrail to everyone except a break-glass role (IAM policy or an SCP)." },
            { text: "Enable log file validation and deliver logs to a bucket the workload account cannot modify (separate account, Object Lock)." },
            { text: "Use a multi-region trail so that a region cannot be used to hide activity." }
        ]
    },
    "T1562.007": {
        id: "T1562.007", name: "Disable or Modify Cloud Firewall", tactic: "Defense Evasion", parent: "Impair Defenses",
        url: "https://attack.mitre.org/techniques/T1562/007/",
        summary: "Network controls are loosened so an attacker can reach resources or move data out.",
        about: [
            "Adversaries disable or modify cloud firewalls to open network paths. Cloud firewalls are virtual controls such as security groups and network ACLs, and anyone with the right permissions can change them with a single API call, with no physical access needed.",
            "A common move is adding an ingress rule that allows broad traffic, to reach a resource from the internet, move laterally or keep a command-and-control channel alive. Egress rules matter too: opening outbound traffic lets data leave. Deleting or recreating a group is another way to remove a restriction without editing it."
        ],
        inAws: "Security groups are the usual target. AuthorizeSecurityGroupIngress and AuthorizeSecurityGroupEgress add rules, the Revoke versions remove them, and CreateSecurityGroup and DeleteSecurityGroup add or remove whole groups. A rule that allows 0.0.0.0/0 on a management port such as SSH or RDP is the classic case.",
        events: ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"],
        examples: [
            { name: "Cryptomining on a cloud account", text: "In a documented case on Google Cloud, an attacker with a compromised service account changed the firewall configuration to allow broad traffic, then launched hundreds of virtual machines for cryptocurrency mining. The same idea applies to AWS security groups." }
        ],
        detection: "Security group changes add points per call: DeleteSecurityGroup 240, AuthorizeSecurityGroupIngress 200, CreateSecurityGroup 160, Authorize/Revoke egress and Revoke ingress 80 to 120. A single change is Low or Medium; a burst of them climbs.",
        response: "Alert only. There is no automatic undo, because reverting a firewall rule without context could break a legitimate change.",
        investigate: [
            "Read the rule itself: protocol, port range and source CIDR. A wide CIDR on SSH, RDP or a database port is the priority.",
            "Find which resources use the group and whether any of them is reachable from the internet.",
            "Compare against a ticket or a Terraform change: an untracked change by a service user is the signal.",
            "Look for the same identity launching instances or changing IAM shortly after."
        ],
        benign: [
            "An engineer opening a port temporarily to debug.",
            "Deployment or autoscaling tools that create and delete groups as part of normal releases."
        ],
        mitigations: [
            { text: "Limit ec2:AuthorizeSecurityGroup* and ec2:DeleteSecurityGroup to a network administration role." },
            { text: "Turn on AWS Config rules that flag security groups open to 0.0.0.0/0 on sensitive ports." },
            { text: "Review changes against a ticket: an unexpected change from a service user is the signal." }
        ]
    },
    "T1485": {
        id: "T1485", name: "Data Destruction", tactic: "Impact", parent: null,
        url: "https://attack.mitre.org/techniques/T1485/",
        summary: "Data is made unrecoverable to interrupt a business or cover tracks.",
        about: [
            "Adversaries destroy data and files on specific systems or across a network to interrupt the availability of systems, services and network resources. The destruction is likely to make data unrecoverable by forensic means, because contents are overwritten and not just unlinked the way a normal delete does.",
            "In cloud environments, adversaries may use their access to delete storage objects, machine images, database instances and other critical infrastructure. When the goal is disruption at scale, the damage is done with the account's own permissions, no malware needed."
        ],
        inAws: "SIEM Lite watches the encryption keys. Disabling a KMS key or scheduling its deletion makes everything encrypted with that key unreadable, without touching a single object. A scheduled deletion is the more dangerous of the two: once the waiting window ends it cannot be undone.",
        events: ["DisableKey", "ScheduleKeyDeletion"],
        examples: [
            { name: "ShinyHunters", text: "Used the DeleteBucket API to delete cloud storage buckets." },
            { name: "LAPSUS$", text: "Deleted target systems and resources, both on premises and in the cloud." },
            { name: "Storm-0501", text: "Destroyed data and backup files." },
            { name: "Wipers (CaddyWiper, KillDisk, Shamoon)", text: "Overwrite files and disk structures on endpoints; the same goal as above, on servers and workstations instead of cloud resources." }
        ],
        detection: "Both KMS calls weigh 400 points, so one of them reaches High on its own and together with another critical action it reaches Critical.",
        response: "Automatic. DisableKey: the key is enabled again. ScheduleKeyDeletion: the deletion is cancelled. The result is stored with the incident.",
        investigate: [
            "Which key, and what does it protect? Check the services that use it (S3, EBS, RDS, Secrets Manager).",
            "Was it a disable or a scheduled deletion? If scheduled, confirm it was cancelled and note when the window would have ended.",
            "Look for batch Delete* or TerminateInstances calls from the same identity: MITRE's detection guidance for the cloud is exactly this.",
            "Verify that recent backups exist and that the same identity cannot delete them."
        ],
        benign: [
            "A planned retirement or rotation of an unused key, which should be tracked and use a long waiting window."
        ],
        mitigations: [
            { id: "M1053", name: "Data Backup", text: "Keep regular backups off the system and protect them from being accessed or destroyed with the same credentials." },
            { id: "M1032", name: "Multi-factor Authentication", text: "Enable MFA Delete on cloud storage such as S3, so irreversible deletions need extra authentication." },
            { id: "M1018", name: "User Account Management", text: "Restrict who can change bucket lifecycle policies; in AWS, consider an SCP limiting PutBucketLifecycle." },
            { text: "Restrict kms:DisableKey and kms:ScheduleKeyDeletion in the key policy and keep the deletion window at 30 days." }
        ]
    },
    "T1110": {
        id: "T1110", name: "Brute Force", tactic: "Credential Access", parent: null,
        url: "https://attack.mitre.org/techniques/T1110/",
        summary: "Repeated attempts to gain access, or to learn what a credential is allowed to do.",
        about: [
            "Adversaries use brute force to gain access to accounts when passwords are unknown or when they hold password hashes. They guess systematically through repeated attempts, either against a live service that validates the credentials or offline against captured data such as hashes.",
            "It can happen at several points of an intrusion: against valid accounts using information from earlier discovery, or combined with externally exposed services as a way in. MITRE lists four sub-techniques: password guessing, password cracking, password spraying and credential stuffing."
        ],
        inAws: "In SIEM Lite, T1110 is a generic label and not proof of password guessing. Any denied API call that does not match a more specific rule is tagged with it, each adding a small base weight of 40 points. Repeated denied calls from one identity and IP look like probing: someone trying actions to learn what a stolen credential is allowed to do.",
        events: ["Any API call that is denied and is not in the other techniques"],
        examples: [
            { name: "ShinyHunters", text: "Brute force against VPN and firewall edge devices." },
            { name: "Storm-0501", text: "Brute force to obtain credentials." },
            { name: "APT41", text: "Brute force against a local administrator account." },
            { name: "Kinsing", text: "SSH brute forcing of hosts, a common first step on exposed servers." },
            { name: "CrackMapExec", text: "A tool that brute forces user credentials across a network range." }
        ],
        detection: "Denied calls are counted per identity and source IP. The label is attached when they repeat, and every call adds the base weight, so a long burst climbs from Low to Medium. It is a signal worth reviewing, not a verdict.",
        response: "Alert only.",
        investigate: [
            "How many denied calls, how fast and against which services? A burst looks like brute force; a slow trickle is often a misconfigured application.",
            "Did a success follow the failures from the same IP or user? That sequence, many failures then a success, is what MITRE's detection guidance looks for.",
            "Is the source IP known? Compare it with the usual addresses and regions of that user.",
            "Check the identity's access keys: when they were created and when they were last used."
        ],
        benign: [
            "A deployment role that is missing one permission and retries in a loop.",
            "Security scanners or inventory tools that probe many APIs on purpose."
        ],
        mitigations: [
            { id: "M1036", name: "Account Use Policies", text: "Lock or throttle accounts after repeated failures, balanced so the lockout itself cannot be used to deny service. Conditional access can block risky sources." },
            { id: "M1032", name: "Multi-factor Authentication", text: "Require MFA, including on externally facing services where possible." },
            { id: "M1027", name: "Password Policies", text: "Follow NIST guidelines when creating password policies." },
            { id: "M1018", name: "User Account Management", text: "Reset accounts found in breached credentials, immediately or after brute force is detected." },
            { text: "Apply least privilege so a stolen identity is denied quickly, remove access keys that are not in use, and alert on bursts of AccessDenied." }
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
