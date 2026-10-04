// Local, more local, variables!
locals {
    trail_name = "${local.prefix}-management-events"
    trail_arn = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
}

resource "aws_s3_bucket" "cloudtrail_logs" {
    count = var.enable_cloudtrail ? 1 : 0
    bucket = "${local.prefix}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
    count = var.enable_cloudtrail ? 1 : 0
    bucket = aws_s3_bucket.cloudtrail_logs[0].id

    rule {
        apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
        }
    }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
    count = var.enable_cloudtrail ? 1 : 0
    bucket = aws_s3_bucket.cloudtrail_logs[0].id

    block_public_acls = true
    ignore_public_acls = true
    block_public_policy = true
    restrict_public_buckets = true
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
    count = var.enable_cloudtrail ? 1 : 0

    statement {
        sid = "AWSCloudTrailAclCheck"
        actions = ["s3:GetBucketAcl"]
        resources = [aws_s3_bucket.cloudtrail_logs[0].arn]

        principals {
            type = "Service"
            identifiers = ["cloudtrail.amazonaws.com"]
        }

        condition {
            test = "StringEquals"
            variable = "AWS:SourceArn"
            values = [local.trail_arn]
        }
    }

    statement {
        sid = "AWSCloudTrailWrite"
        actions = ["s3:PutObject"]
        resources = ["${aws_s3_bucket.cloudtrail_logs[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

        principals {
            type = "Service"
            identifiers = ["cloudtrail.amazonaws.com"]
        }

        condition {
            test = "StringEquals"
            variable = "AWS:SourceArn"
            values = [local.trail_arn]
        }

        condition {
            test = "StringEquals"
            variable = "s3:x-amz-acl"
            values = ["bucket-owner-full-control"]
        }
    }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
    count = var.enable_cloudtrail ? 1 : 0
    bucket = aws_s3_bucket.cloudtrail_logs[0].id
    policy = data.aws_iam_policy_document.cloudtrail_bucket[0].json
}

resource "aws_cloudtrail" "management_events" {
    count = var.enable_cloudtrail ? 1 : 0
    name = local.trail_name
    s3_bucket_name = aws_s3_bucket.cloudtrail_logs[0].id
    is_multi_region_trail = true
    include_global_service_events = true
    enable_log_file_validation = true

    advanced_event_selector {
        name = "Management events selector"

        field_selector {
            field = "eventCategory"
            equals = ["Management"]
        }
    }

    depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}