# CloudWatch alarms of the query path. CloudWatch cannot publish to a topic encrypted with the AWS managed key
# (alias/aws/sns), so the alarms use their own topic instead of the incident alerts topic
resource "aws_sns_topic" "ops" {
    # checkov:skip=CKV_AWS_26:CloudWatch alarms cannot publish to a topic encrypted with an AWS managed key, and a CMK is DEBT for 1.1. The messages only carry alarm names and counters
    name = "${local.prefix}-ops-alarms"
}

resource "aws_sns_topic_subscription" "ops_email" {
    topic_arn = aws_sns_topic.ops.arn
    protocol = "email"
    endpoint = var.alert_email
}

# Server errors of the API, the handlers return 500 on any unexpected exception
resource "aws_cloudwatch_metric_alarm" "api_5xx" {
    alarm_name = "${local.prefix}-api-5xx"
    alarm_description = "The API returned 5XX errors"
    namespace = "AWS/ApiGateway"
    metric_name = "5xx"
    dimensions = {
        ApiId = aws_apigatewayv2_api.this.id
        Stage = aws_apigatewayv2_stage.default.name
    }
    statistic = "Sum"
    period = 300
    evaluation_periods = 1
    threshold = 1
    comparison_operator = "GreaterThanOrEqualToThreshold"
    treat_missing_data = "notBreaching"
    alarm_actions = [aws_sns_topic.ops.arn]
}

# A burst of 4XX is someone scanning the API or a broken client (401 without token, 400 bad input, 429 throttled)
resource "aws_cloudwatch_metric_alarm" "api_4xx" {
    alarm_name = "${local.prefix}-api-4xx"
    alarm_description = "Unusually many 4XX responses from the API"
    namespace = "AWS/ApiGateway"
    metric_name = "4xx"
    dimensions = {
        ApiId = aws_apigatewayv2_api.this.id
        Stage = aws_apigatewayv2_stage.default.name
    }
    statistic = "Sum"
    period = 300
    evaluation_periods = 1
    threshold = 100
    comparison_operator = "GreaterThanOrEqualToThreshold"
    treat_missing_data = "notBreaching"
    alarm_actions = [aws_sns_topic.ops.arn]
}

# Crashes and timeouts never reach the handler's own error response, so they only show here
resource "aws_cloudwatch_metric_alarm" "api_lambda_errors" {
    for_each = aws_lambda_function.api
    alarm_name = "${local.prefix}-${each.key}-lambda-errors"
    alarm_description = "The ${each.key} API function failed"
    namespace = "AWS/Lambda"
    metric_name = "Errors"
    dimensions = {
        FunctionName = each.value.function_name
    }
    statistic = "Sum"
    period = 300
    evaluation_periods = 1
    threshold = 1
    comparison_operator = "GreaterThanOrEqualToThreshold"
    treat_missing_data = "notBreaching"
    alarm_actions = [aws_sns_topic.ops.arn]
}
