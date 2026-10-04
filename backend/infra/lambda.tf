locals {
    runtime = "python3.14"
    functions_with_shared = toset(["detection", "baseline_updater", "incident_consolidator"])
    functions_standalone = toset(["incident_exporter", "weekly_summary", "soar_response"])
}

# Functions that import the shared package: handler at the zip root, shared/ next to it
data "archive_file" "with_shared" {
    for_each = local.functions_with_shared
    type = "zip"
    output_path = "${path.module}/build/${each.key}.zip"

    source {
        content = file("${path.module}/../functions/pipeline/${each.key}/handler.py")
        filename = "handler.py"
    }

    dynamic "source" {
        for_each = fileset("${path.module}/../shared", "*.py")
        content {
            content = file("${path.module}/../shared/${source.value}")
            filename = "shared/${source.value}"
        }
    }
}

# Functions with no local imports: the folder is zipped as is
data "archive_file" "standalone" {
    for_each = local.functions_standalone
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
    filename = data.archive_file.with_shared["detection"].output_path
    source_code_hash = data.archive_file.with_shared["detection"].output_base64sha256

    environment {
        variables = {
            THRESHOLD_TABLE_NAME = aws_dynamodb_table.threshold_tracker.name
            BASELINE_TABLE_NAME = aws_dynamodb_table.behavior_baseline.name
            SOAR_RESPONSE_FUNCTION_NAME = aws_lambda_function.soar_response.function_name
            ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
            ENABLE_BEHAVIOR_BASELINE = tostring(var.enable_behavior_baseline)
            BASELINE_N0_DAYS = tostring(var.baseline_n0_days)
            BASELINE_Z_LOW = tostring(var.baseline_z_low)
            BASELINE_Z_HIGH = tostring(var.baseline_z_high)
            BASELINE_TIME_AMPLITUDE = tostring(var.baseline_time_amplitude)
            BASELINE_IP_BUMP_SAME_RANGE = tostring(var.baseline_ip_bump_same_range)
            BASELINE_IP_BUMP_NEW_RANGE = tostring(var.baseline_ip_bump_new_range)
            BASELINE_M_MAX = tostring(var.baseline_m_max)
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
    filename = data.archive_file.with_shared["baseline_updater"].output_path
    source_code_hash = data.archive_file.with_shared["baseline_updater"].output_base64sha256

    environment {
        variables = {
            BASELINE_TABLE_NAME = aws_dynamodb_table.behavior_baseline.name
            IP_TTL_DAYS = tostring(var.ip_ttl_days)
            BASELINE_Z_LOW = tostring(var.baseline_z_low)
            BASELINE_Z_HIGH = tostring(var.baseline_z_high)
            BASELINE_IP_BUMP_SAME_RANGE = tostring(var.baseline_ip_bump_same_range)
            BASELINE_IP_BUMP_NEW_RANGE = tostring(var.baseline_ip_bump_new_range)
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
    filename = data.archive_file.with_shared["incident_consolidator"].output_path
    source_code_hash = data.archive_file.with_shared["incident_consolidator"].output_base64sha256

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
    filename = data.archive_file.standalone["incident_exporter"].output_path
    source_code_hash = data.archive_file.standalone["incident_exporter"].output_base64sha256

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
    filename = data.archive_file.standalone["weekly_summary"].output_path
    source_code_hash = data.archive_file.standalone["weekly_summary"].output_base64sha256

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
    filename = data.archive_file.standalone["soar_response"].output_path
    source_code_hash = data.archive_file.standalone["soar_response"].output_base64sha256

    environment {
        variables = {
            THRESHOLD_TABLE_NAME = aws_dynamodb_table.threshold_tracker.name
        }
    }
}

# Streams triggers: the function is invoked by DynamoDB, not by EventBridge
resource "aws_lambda_event_source_mapping" "incident_consolidator" {
    event_source_arn = aws_dynamodb_table.threshold_tracker.stream_arn
    function_name = aws_lambda_function.incident_consolidator.arn
    starting_position = "LATEST"
    batch_size = 1

    # Only real TTL expirations: removals done by the DynamoDB service itself
    filter_criteria {
        filter {
            pattern = jsonencode({
                eventName = ["REMOVE"]
                userIdentity = {
                    type = ["Service"]
                    principalId = ["dynamodb.amazonaws.com"]
                }
            })
        }
    }
}

resource "aws_lambda_event_source_mapping" "incident_exporter" {
    event_source_arn = aws_dynamodb_table.incident_reports.stream_arn
    function_name = aws_lambda_function.incident_exporter.arn
    starting_position = "LATEST"
    batch_size = 100
}