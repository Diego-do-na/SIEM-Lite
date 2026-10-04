resource "aws_cloudwatch_event_rule" "config_changes" {
    name = "${local.prefix}-config-changes"
    state = var.enable_event_rules ? "ENABLED" : "DISABLED"

    event_pattern = jsonencode({
        source = ["aws.cloudtrail", "aws.ec2", "aws.kms"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
            eventSource = ["cloudtrail.amazonaws.com", "ec2.amazonaws.com", "kms.amazonaws.com"]
            eventName = [
                "StopLogging", "DeleteTrail", "UpdateTrail",
                "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
                "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
                "CreateSecurityGroup", "DeleteSecurityGroup",
                "DisableKey", "ScheduleKeyDeletion"
            ]
        }
    })
}

resource "aws_cloudwatch_event_rule" "denied_access" {
    name = "${local.prefix}-denied-access"
    state = var.enable_event_rules ? "ENABLED" : "DISABLED"

    event_pattern = jsonencode({
        source = ["aws.s3", "aws.iam", "aws.ec2", "aws.kms", "aws.sts"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
            errorCode = ["AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess"]
        }
    })
}

resource "aws_cloudwatch_event_rule" "baseline_feed" {
    name = "${local.prefix}-baseline-feed"
    state = var.enable_event_rules ? "ENABLED" : "DISABLED"

    event_pattern = jsonencode({
        source = [
            "aws.iam", "aws.s3", "aws.ec2", "aws.kms", "aws.cloudtrail", "aws.sts",
            "aws.lambda", "aws.dynamodb", "aws.sns", "aws.events", "aws.logs",
            "aws.config", "aws.bedrock", "aws.signin"
        ]
        detail-type = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
        detail = {
            errorCode = [{ exists = false }]
            errorMessage = [{ exists = false }]
            eventName = [{
                anything-but = [
                    "StopLogging", "DeleteTrail", "DisableKey", "ScheduleKeyDeletion",
                    "UpdateTrail", "CreateSecurityGroup", "DeleteSecurityGroup",
                    "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
                    "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress"
                ]
            }]
        }
    })
}

resource "aws_cloudwatch_event_rule" "weekly_summary" {
    name = "${local.prefix}-weekly-summary-trigger"
    schedule_expression = "cron(0 7 ? * SUN *)"
    state = var.enable_event_rules ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "config_changes" {
    rule = aws_cloudwatch_event_rule.config_changes.name
    arn = aws_lambda_function.detection.arn
}

resource "aws_cloudwatch_event_target" "denied_access" {
    rule = aws_cloudwatch_event_rule.denied_access.name
    arn = aws_lambda_function.detection.arn
}

resource "aws_cloudwatch_event_target" "baseline_feed" {
    rule = aws_cloudwatch_event_rule.baseline_feed.name
    arn = aws_lambda_function.baseline_updater.arn
}

resource "aws_cloudwatch_event_target" "weekly_summary" {
    rule = aws_cloudwatch_event_rule.weekly_summary.name
    arn = aws_lambda_function.weekly_summary.arn
}

resource "aws_lambda_permission" "config_changes" {
    statement_id = "AllowEventBridgeConfigChanges"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.detection.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.config_changes.arn
}

resource "aws_lambda_permission" "denied_access" {
    statement_id = "AllowEventBridgeDeniedAccess"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.detection.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.denied_access.arn
}

resource "aws_lambda_permission" "baseline_feed" {
    statement_id = "AllowEventBridgeBaselineFeed"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.baseline_updater.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.baseline_feed.arn
}

resource "aws_lambda_permission" "weekly_summary" {
    statement_id = "AllowEventBridgeWeeklySummary"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.weekly_summary.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.weekly_summary.arn
}