output "alerts_topic_arn" {
    description = "SNS topic that receives the alerts"
    value = aws_sns_topic.alerts.arn
}

output "dynamodb_tables" {
    description = "DynamoDB tables"
    value = {
        threshold_tracker = aws_dynamodb_table.threshold_tracker.name
        behavior_baseline = aws_dynamodb_table.behavior_baseline.name
        incident_reports = aws_dynamodb_table.incident_reports.name
    }
}

output "s3_buckets" {
    description = "Data buckets"
    value = {
        raw = aws_s3_bucket.raw.bucket
        processed = aws_s3_bucket.processed.bucket
        athena_results = aws_s3_bucket.athena_results.bucket
    }
}

output "lambda_functions" {
    description = "Lambda function names"
    value = {
        detection = aws_lambda_function.detection.function_name
        baseline_updater = aws_lambda_function.baseline_updater.function_name
        incident_consolidator = aws_lambda_function.incident_consolidator.function_name
        incident_exporter = aws_lambda_function.incident_exporter.function_name
        weekly_summary = aws_lambda_function.weekly_summary.function_name
        soar_response = aws_lambda_function.soar_response.function_name
    }
}

output "athena_workgroup" {
    description = "Athena workgroup used by the weekly summary"
    value = aws_athena_workgroup.this.name
}

output "api_url" {
    description = "Base URL of the HTTP API"
    value = aws_apigatewayv2_api.this.api_endpoint
}

output "cognito_user_pool_id" {
    description = "Cognito user pool of the dashboard"
    value = aws_cognito_user_pool.this.id
}

output "cognito_client_id" {
    description = "Cognito app client the dashboard logs in with"
    value = aws_cognito_user_pool_client.dashboard.id
}

output "cognito_login_url" {
    description = "Base URL of the Cognito hosted login page"
    value = local.cognito_login_url
}

output "frontend_url" {
    description = "Where the dashboard is served (HTTPS, through CloudFront)"
    value = local.frontend_origin
}