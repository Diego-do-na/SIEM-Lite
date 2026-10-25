locals {
    # Route key => function. Public routes are listed apart so that Checkov still verifies that every other route has auth
    api_public_routes = {
        "GET /health" = "health"
    }

    api_protected_routes = {
        "GET /incidents" = "incidents"
        "GET /incidents/{severity}/{timestamp}" = "incidents"
        "GET /stats" = "stats"
        "GET /analytics/{report}" = "analytics"
    }
}

resource "aws_apigatewayv2_api" "this" {
    name = "${local.prefix}-api"
    protocol_type = "HTTP"

    cors_configuration {
        allow_origins = local.dashboard_origins
        allow_methods = ["GET", "OPTIONS"]
        allow_headers = ["authorization", "content-type"]
        max_age = 3600
    }
}

# Validates signature, expiry and client of the access token before any Lambda runs.
# The group (admin or viewer) is read inside the Lambda
resource "aws_apigatewayv2_authorizer" "cognito" {
    api_id = aws_apigatewayv2_api.this.id
    name = "cognito"
    authorizer_type = "JWT"
    identity_sources = ["$request.header.Authorization"]

    jwt_configuration {
        audience = [aws_cognito_user_pool_client.dashboard.id]
        issuer = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
    }
}

resource "aws_apigatewayv2_integration" "this" {
    for_each = aws_lambda_function.api
    api_id = aws_apigatewayv2_api.this.id
    integration_type = "AWS_PROXY"
    integration_uri = each.value.invoke_arn
    payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "public" {
    # checkov:skip=CKV_AWS_309:GET /health is public on purpose, it returns a fixed status and touches no data
    for_each = local.api_public_routes
    api_id = aws_apigatewayv2_api.this.id
    route_key = each.key
    target = "integrations/${aws_apigatewayv2_integration.this[each.value].id}"
    authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "protected" {
    for_each = local.api_protected_routes
    api_id = aws_apigatewayv2_api.this.id
    route_key = each.key
    target = "integrations/${aws_apigatewayv2_integration.this[each.value].id}"
    authorization_type = "JWT"
    authorizer_id = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_cloudwatch_log_group" "api_access" {
    # checkov:skip=CKV_AWS_158:DEBT for 1.1, encrypting the log group needs a CMK, planned together with the other CMK work
    name = "/aws/apigateway/${local.prefix}-api"
    retention_in_days = 365
}

resource "aws_apigatewayv2_stage" "default" {
    api_id = aws_apigatewayv2_api.this.id
    name = "$default"
    auto_deploy = true

    # Caps the request rate, so a flood cannot turn into a bill
    default_route_settings {
        throttling_rate_limit = 10
        throttling_burst_limit = 20
    }

    access_log_settings {
        destination_arn = aws_cloudwatch_log_group.api_access.arn
        format = jsonencode({
            requestId = "$context.requestId"
            ip = "$context.identity.sourceIp"
            requestTime = "$context.requestTime"
            routeKey = "$context.routeKey"
            status = "$context.status"
            responseLength = "$context.responseLength"
            integrationError = "$context.integrationErrorMessage"
        })
    }
}

resource "aws_lambda_permission" "api" {
    for_each = aws_lambda_function.api
    statement_id = "AllowApiGateway"
    action = "lambda:InvokeFunction"
    function_name = each.value.function_name
    principal = "apigateway.amazonaws.com"
    source_arn = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
}
