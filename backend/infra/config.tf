resource "aws_s3_bucket" "config" {
    count = var.enable_config ? 1 : 0
    bucket = "${local.prefix}-config-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
    count = var.enable_config ? 1 : 0
    bucket = aws_s3_bucket.config[0].id

    rule {
        apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
        }
    }
}

resource "aws_s3_bucket_public_access_block" "config" {
    count = var.enable_config ? 1 : 0
    bucket = aws_s3_bucket.config[0].id

    block_public_acls = true
    ignore_public_acls = true
    block_public_policy = true
    restrict_public_buckets = true
}

data "aws_iam_policy_document" "config_assume" {
    statement {
        actions = ["sts:AssumeRole"]
        principals {
            type = "Service"
            identifiers = ["config.amazonaws.com"]
        }
    }
}

resource "aws_iam_role" "config" {
    count = var.enable_config ? 1 : 0
    name = "${local.prefix}-config"
    assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config" {
    count = var.enable_config ? 1 : 0
    role = aws_iam_role.config[0].name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_delivery" {
    count = var.enable_config ? 1 : 0

    statement {
        actions = ["s3:PutObject"]
        resources = ["${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
    }

    statement {
        actions = ["s3:GetBucketAcl"]
        resources = [aws_s3_bucket.config[0].arn]
    }
}

resource "aws_iam_role_policy" "config_delivery" {
    count = var.enable_config ? 1 : 0
    name = "config-delivery"
    role = aws_iam_role.config[0].id
    policy = data.aws_iam_policy_document.config_delivery[0].json
}

resource "aws_config_configuration_recorder" "this" {
    count = var.enable_config ? 1 : 0
    name = "${local.prefix}-recorder"
    role_arn = aws_iam_role.config[0].arn

    # Only trails, to keep the cost down (SOAR only needs the trail history)
    recording_group {
        all_supported = false
        resource_types = ["AWS::CloudTrail::Trail"]
    }
}

resource "aws_config_delivery_channel" "this" {
    count = var.enable_config ? 1 : 0
    name = "${local.prefix}-channel"
    s3_bucket_name = aws_s3_bucket.config[0].id

    depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
    count = var.enable_config ? 1 : 0
    name = aws_config_configuration_recorder.this[0].name
    is_enabled = true

    depends_on = [aws_config_delivery_channel.this]
}