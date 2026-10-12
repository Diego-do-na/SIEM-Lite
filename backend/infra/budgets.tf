# The project is meant to cost around one dollar a month. This warns long before it does not.
# The budget covers the whole account, so keep it in a dedicated account or set the limit accordingly
resource "aws_budgets_budget" "monthly" {
    name = "${local.prefix}-monthly"
    budget_type = "COST"
    limit_amount = tostring(var.monthly_budget_usd)
    limit_unit = "USD"
    time_unit = "MONTHLY"

    notification {
        comparison_operator = "GREATER_THAN"
        threshold = 80
        threshold_type = "PERCENTAGE"
        notification_type = "ACTUAL"
        subscriber_email_addresses = [var.alert_email]
    }

    notification {
        comparison_operator = "GREATER_THAN"
        threshold = 100
        threshold_type = "PERCENTAGE"
        notification_type = "FORECASTED"
        subscriber_email_addresses = [var.alert_email]
    }
}
