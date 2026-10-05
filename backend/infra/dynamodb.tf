resource "aws_dynamodb_table" "threshold_tracker" {
    name = "${local.prefix}-threshold-tracker"
    billing_mode = "PAY_PER_REQUEST"
    hash_key = "userIdentity"
    range_key = "sourceIPAddress"

    attribute {
        name = "userIdentity"
        type = "S"
    }

    attribute {
        name = "sourceIPAddress"
        type = "S"
    }

    ttl {
        attribute_name = "ttl"
        enabled = true
    }

    point_in_time_recovery {
        enabled = true
    }

    stream_enabled = true
    stream_view_type = "NEW_AND_OLD_IMAGES"
}

resource "aws_dynamodb_table" "behavior_baseline" {
    name = "${local.prefix}-behavior-baseline"
    billing_mode = "PAY_PER_REQUEST"
    hash_key = "userIdentity"
    range_key = "recordType"

    attribute {
        name = "userIdentity"
        type = "S"
    }

    attribute {
        name = "recordType"
        type = "S"
    }

    ttl {
        attribute_name = "ttl"
        enabled = true
    }

    point_in_time_recovery {
        enabled = true
    }
}

resource "aws_dynamodb_table" "incident_reports" {
    name = "${local.prefix}-incident-reports"
    billing_mode = "PAY_PER_REQUEST"
    hash_key = "severity"
    range_key = "timestamp"

    attribute {
        name = "severity"
        type = "S"
    }

    attribute {
        name = "timestamp"
        type = "N"
    }

    point_in_time_recovery {
        enabled = true
    }

    stream_enabled = true
    stream_view_type = "NEW_AND_OLD_IMAGES"
}