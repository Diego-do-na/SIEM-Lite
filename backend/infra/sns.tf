resource "aws_sns_topic" "alerts" {
    name = "${local.prefix}-alerts"
}

resource "aws_sns_topic_subscription" "alert_email" {
    topic_arn = aws_sns_topic.alerts.arn
    protocol = "email"
    endpoint = var.alert_email
}