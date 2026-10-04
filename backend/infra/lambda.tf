locals {
    runtime = "python3.14"
    function_dirs = toset([
        "detection", "baseline_updater", "incident_consolidator",
        "incident_exporter", "weekly_summary", "soar_response"
    ])
}

# One zip per function folder. Terraform detects code changes through the hash.
data "archive_file" "this" {
    for_each = local.function_dirs
    type = "zip"
    source_dir = "${path.module}/../functions/pipeline/${each.key}"
    output_path = "${path.module}/build/${each.key}.zip"
}

resource "aws_lambda_function" "detection" {
    function_name = "${local.prefix}-detection"
    role = aws_iam_role.lambda["detection"].arn
    runtime = local.runtime
    handler = "handler.lambda_handler"
    timeout = 10
    memory_size = 128
    filename = data.archive_file.this["detection"].output_path
    source_code_hash = data.archive_file.this["detection"].output_base64sha256

    environment {
        variables = {
            THRESHOLD_TABLE_NAME = aws_dynamodb_table.threshold_tracker.name
            BASELINE_TABLE_NAME = aws_dynamodb_table.behavior_baseline.name
            SOAR_RESPONSE_FUNCTION_NAME = aws_lambda_function.soar_response.function_name
            ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
            ENABLE_BEHAVIOR_BASELINE = tostring(var.enable_behavior_baseline)
            BASELINE_N0_DAYS = tostring(var.baseline_n0_days)
        }
    }
}

resource "aws_lambda_function" "baseline_updater" {
    function_name = "${local.prefix}-baseline-updater"
    role = aws_iam_role.lambda["baseline_updater"].arn
    runtime = local.runtime
    handler = "handler.lambda_handler"
    timeout = 10
    memory_size = 128
    filename = data.archive_file.this["baseline_updater"].output_path
    source_code_hash = data.archive_file.this["baseline_updater"].output_base64sha256

    environment {
        variables = {
            BASELINE_TABLE_NAME = aws_dynamodb_table.behavior_baseline.name
            IP_TTL_DAYS = tostring(var.ip_ttl_days)
        }
    }
}

resource "aws_lambda_function" "incident_consolidator" {
    function_name = "${local.prefix}-incident-consolidator"
    role = aws_iam_role.lambda["incident_consolidator"].arn
    runtime = local.runtime
    handler = "handler.lambda_handler"
    timeout = 30
    memory_size = 128
    filename = data.archive_file.this["incident_consolidator"].output_path
    source_code_hash = data.archive_file.this["incident_consolidator"].output_base64sha256

    environment {
        variables = {
            INCIDENT_TABLE_NAME = aws_dynamodb_table.incident_reports.arn
            BEDROCK_MODEL_ID = var.bedrock_model_id
        }
    }
}

resource "aws_lambda_function" "incident_exporter" {
    function_name = "${local.prefix}-incident-exporter"
    role = aws_iam_role.lambda["incident_exporter"].arn
    runtime = local.runtime
    handler = "handler.lambda_handler"
    timeout = 10
    memory_size = 128
    filename = data.archive_file.this["incident_exporter"].output_path
    source_code_hash = data.archive_file.this["incident_exporter"].output_base64sha256

    environment {
        variables = {
            RAW_BUCKET_NAME = aws_s3_bucket.raw.bucket
        }
    }
}

resource "aws_lambda_function" "weekly_summary" {
    function_name = "${local.prefix}-weekly-summary"
    role = aws_iam_role.lambda["weekly_summary"].arn
    runtime = local.runtime
    handler = "handler.lambda_handler"
    timeout = 30
    memory_size = 128
    filename = data.archive_file.this["weekly_summary"].output_path
    source_code_hash = data.archive_file.this["weekly_summary"].output_base64sha256

    environment {
        variables = {
            SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
            ATHENA_DATABASE = aws_glue_catalog_database.catalog.name
            # The crawler names the table after the bucket, with dashes turned into underscores
            ATHENA_TABLE = replace(aws_s3_bucket.processed.bucket, "-", "_")
            ATHENA_OUTPUT_LOCATION = "s3://${aws_s3_bucket.athena_results.bucket}/"
            BEDROCK_MODEL_ID = var.bedrock_model_id
        }
    }
}

resource "aws_lambda_function" "soar_response" {
    function_name = "${local.prefix}-soar-response"
    role = aws_iam_role.lambda["soar_response"].arn
    runtime = local.runtime
    handler = "handler.lambda_handler"
    timeout = 15
    memory_size = 128
    filename = data.archive_file.this["soar_response"].output_path
    source_code_hash = data.archive_file.this["soar_response"].output_base64sha256

    environment {
        variables = {
            THRESHOLD_TABLE_NAME = aws_dynamodb_table.threshold_tracker.name
        }
    }
}