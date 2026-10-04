locals {
    lambda_roles = toset([
        "detection", "baseline_updater", "incident_consolidator",
        "incident_exporter", "weekly_summary", "soar_response"
    ])

    # Bedrock: the inference profile plus the foundation model behind it (any region, since the "us." profile routes across regions)
    bedrock_resources = [
        "arn:aws:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/${var.bedrock_model_id}",
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6"
    ]
}

data "aws_iam_policy_document" "lambda_assume" {
    statement {
        actions = ["sts:AssumeRole"]
        principals {
            type = "Service"
            identifiers = ["lambda.amazonaws.com"]
        }
    }
}

data "aws_iam_policy_document" "glue_assume" {
    statement {
        actions = ["sts:AssumeRole"]
        principals {
            type = "Service"
            identifiers = ["glue.amazonaws.com"]
        }
        # Confused deputy protection: only Glue acting for this account can use the role
        condition {
            test = "StringEquals"
            variable = "aws:SourceAccount"
            values = [data.aws_caller_identity.current.account_id]
        }
    }
}

resource "aws_iam_role" "lambda" {
    for_each = local.lambda_roles
    name = "${local.prefix}-${replace(each.key, "_", "-")}"
    assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
    for_each = aws_iam_role.lambda
    role = each.value.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# detection: reads the baseline, updates the tracker, publishes alerts, invokes SOAR
data "aws_iam_policy_document" "detection" {
    statement {
        actions = ["dynamodb:Query"]
        resources = [aws_dynamodb_table.behavior_baseline.arn]
    }
    statement {
        actions = ["dynamodb:UpdateItem"]
        resources = [aws_dynamodb_table.threshold_tracker.arn]
    }
    statement {
        actions = ["sns:Publish"]
        resources = [aws_sns_topic.alerts.arn]
    }
    statement {
        actions = ["lambda:InvokeFunction"]
        resources = [aws_lambda_function.soar_response.arn]
    }
}

resource "aws_iam_role_policy" "detection" {
    name = "detection"
    role = aws_iam_role.lambda["detection"].id
    policy = data.aws_iam_policy_document.detection.json
}

# baseline_updater: only writes to the baseline table
data "aws_iam_policy_document" "baseline_updater" {
    statement {
        actions = ["dynamodb:UpdateItem"]
        resources = [aws_dynamodb_table.behavior_baseline.arn]
    }
}

resource "aws_iam_role_policy" "baseline_updater" {
    name = "baseline-updater"
    role = aws_iam_role.lambda["baseline_updater"].id
    policy = data.aws_iam_policy_document.baseline_updater.json
}

# incident_consolidator: reads the tracker stream, writes incidents, calls Bedrock
data "aws_iam_policy_document" "incident_consolidator" {
    statement {
        actions = ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream"]
        resources = [aws_dynamodb_table.threshold_tracker.stream_arn]
    }
    statement {
        # ListStreams does not support resource-level permissions
        actions = ["dynamodb:ListStreams"]
        resources = ["*"]
    }
    statement {
        actions = ["dynamodb:PutItem"]
        resources = [aws_dynamodb_table.incident_reports.arn]
    }
    statement {
        actions = ["bedrock:InvokeModel"]
        resources = local.bedrock_resources
    }
    statement {
        # Marketplace actions do not support resource-level permissions
        actions = ["aws-marketplace:ViewSubscriptions", "aws-marketplace:Subscribe"]
        resources = ["*"]
    }
}

resource "aws_iam_role_policy" "incident_consolidator" {
    name = "incident-consolidator"
    role = aws_iam_role.lambda["incident_consolidator"].id
    policy = data.aws_iam_policy_document.incident_consolidator.json
}

# incident_exporter: reads the incident stream, writes to the raw bucket
data "aws_iam_policy_document" "incident_exporter" {
    statement {
        actions = ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream"]
        resources = [aws_dynamodb_table.incident_reports.stream_arn]
    }
    statement {
        actions = ["dynamodb:ListStreams"]
        resources = ["*"]
    }
    statement {
        actions = ["s3:PutObject"]
        resources = ["${aws_s3_bucket.raw.arn}/*"]
    }
}

resource "aws_iam_role_policy" "incident_exporter" {
    name = "incident-exporter"
    role = aws_iam_role.lambda["incident_exporter"].id
    policy = data.aws_iam_policy_document.incident_exporter.json
}

# weekly_summary: queries Athena, reads the processed data, calls Bedrock, publishes the report
data "aws_iam_policy_document" "weekly_summary" {
    statement {
        actions = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults"]
        resources = ["arn:aws:athena:${var.aws_region}:${data.aws_caller_identity.current.account_id}:workgroup/primary"]
    }
    statement {
        actions = ["glue:GetDatabase", "glue:GetTable", "glue:GetPartitions"]
        resources = [
            "arn:aws:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:catalog",
            aws_glue_catalog_database.catalog.arn,
            "arn:aws:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${aws_glue_catalog_database.catalog.name}/*"
        ]
    }
    statement {
        actions = ["s3:GetObject"]
        resources = ["${aws_s3_bucket.processed.arn}/*"]
    }
    statement {
        actions = ["s3:ListBucket"]
        resources = [aws_s3_bucket.processed.arn]
    }
    statement {
        actions = ["s3:GetObject", "s3:PutObject"]
        resources = ["${aws_s3_bucket.athena_results.arn}/*"]
    }
    statement {
        actions = ["s3:ListBucket", "s3:GetBucketLocation"]
        resources = [aws_s3_bucket.athena_results.arn]
    }
    statement {
        actions = ["sns:Publish"]
        resources = [aws_sns_topic.alerts.arn]
    }
    statement {
        actions = ["bedrock:InvokeModel"]
        resources = local.bedrock_resources
    }
}

resource "aws_iam_role_policy" "weekly_summary" {
    name = "weekly-summary"
    role = aws_iam_role.lambda["weekly_summary"].id
    policy = data.aws_iam_policy_document.weekly_summary.json
}

# soar_response: remediates the four critical actions and records what it did
data "aws_iam_policy_document" "soar_response" {
    statement {
        # The target trail or key is not known in advance, so these cannot be scoped to a resource
        actions = ["cloudtrail:StartLogging", "cloudtrail:GetTrailStatus", "cloudtrail:CreateTrail"]
        resources = ["*"]
    }
    statement {
        actions = ["kms:EnableKey", "kms:CancelKeyDeletion"]
        resources = ["*"]
    }
    statement {
        # GetResourceConfigHistory does not support resource-level permissions
        actions = ["config:GetResourceConfigHistory"]
        resources = ["*"]
    }
    statement {
        actions = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        resources = [aws_dynamodb_table.threshold_tracker.arn]
    }
}

resource "aws_iam_role_policy" "soar_response" {
    name = "soar-response"
    role = aws_iam_role.lambda["soar_response"].id
    policy = data.aws_iam_policy_document.soar_response.json
}

# Glue: one role shared by the transformer Job and the crawler
resource "aws_iam_role" "glue" {
    name = "${local.prefix}-glue"
    assume_role_policy = data.aws_iam_policy_document.glue_assume.json
}

resource "aws_iam_role_policy_attachment" "glue_service" {
    role = aws_iam_role.glue.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

data "aws_iam_policy_document" "glue_data" {
    statement {
        actions = ["s3:GetObject"]
        resources = ["${aws_s3_bucket.raw.arn}/*"]
    }
    statement {
        actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        resources = ["${aws_s3_bucket.processed.arn}/*", "${aws_s3_bucket.glue_assets.arn}/*"]
    }
    statement {
        actions = ["s3:ListBucket"]
        resources = [aws_s3_bucket.raw.arn, aws_s3_bucket.processed.arn, aws_s3_bucket.glue_assets.arn]
    }
}

resource "aws_iam_role_policy" "glue_data" {
    name = "glue-data"
    role = aws_iam_role.glue.id
    policy = data.aws_iam_policy_document.glue_data.json
}