variable "aws_region" {
    description = "AWS region where the infrastructure is deployed"
    type = string
}

variable "project_name" {
    description = "Project name, used as a prefix for resources"
    type = string
    default = "siem-lite"
}

variable "environment" {
    description = "Deployment environment (dev, staging, prod)"
    type = string
    default = "dev"
}

variable "alert_email" {
    description = "Email address that receives SNS alerts"
    type = string
    sensitive = true
}

variable "bedrock_model_id" {
    description = "Bedrock inference profile ID used for triage and insights"
    type = string
    default = "us.anthropic.claude-sonnet-4-6"
}

variable "ip_ttl_days" {
    description = "Days an IP record lives in the baseline before expiring via TTL"
    type = number
    default = 30
}

variable "enable_behavior_baseline" {
    description = "Flag to enable/disable the behavior multiplier (Rule 3)"
    type = bool
}

variable "baseline_n0_days" {
    description = "Days of activity until full confidence (100%) in the baseline"
    type = number
    default = 14
}

variable "baseline_z_low" {
    description = "Z-score considered clearly normal"
    type = number
    default = 1.0
}

variable "baseline_z_high" {
    description = "Z-score considered clearly anomalous"
    type = number
    default = 3.0
}

variable "baseline_time_amplitude" {
    description = "Amplitude of the time-of-day multiplier (1 +/- this value)"
    type = number
    default = 0.5
}

variable "baseline_ip_bump_same_range" {
    description = "Multiplier bump for a new IP within an already-known range"
    type = number
    default = 0.25
}

variable "baseline_ip_bump_new_range" {
    description = "Multiplier bump for an IP in a never-seen range"
    type = number
    default = 0.75
}

variable "baseline_m_max" {
    description = "Global cap on the behavior multiplier"
    type = number
    default = 2.0
}

variable "tags" {
    description = "Common tags applied to all resources"
    type = map(string)
    default = {
        Project = "siem-lite"
    }
}

variable "enable_cloudtrail" {
    description = "Create a CloudTrail trail and its log bucket. Keep false if the account already has a multi-region management trail"
    type = bool
    default = false
}