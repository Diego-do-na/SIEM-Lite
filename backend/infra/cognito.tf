resource "aws_cognito_user_pool" "this" {
    name = "${local.prefix}-users"
    username_attributes = ["email"]
    auto_verified_attributes = ["email"]
    mfa_configuration = "OFF"
    # Keeps terraform destroy working in test deployments
    deletion_protection = "INACTIVE"

    admin_create_user_config {
        # Nobody can sign up on their own: the admin is created below, any other user is created by an admin
        allow_admin_create_user_only = true
    }

    password_policy {
        minimum_length = 12
        require_lowercase = true
        require_uppercase = true
        require_numbers = true
        require_symbols = true
        temporary_password_validity_days = 7
    }

    account_recovery_setting {
        recovery_mechanism {
            name = "verified_email"
            priority = 1
        }
    }
}

# Hosted login page. The account id keeps the domain unique, since the domain prefix is global per region
resource "aws_cognito_user_pool_domain" "this" {
    domain = "${local.prefix}-${data.aws_caller_identity.current.account_id}"
    user_pool_id = aws_cognito_user_pool.this.id
    # 1 is the classic hosted UI, which works without extra branding setup
    managed_login_version = 1
}

# The dashboard is a static page, so the client has no secret: PKCE protects the code exchange instead
resource "aws_cognito_user_pool_client" "dashboard" {
    name = "${local.prefix}-dashboard"
    user_pool_id = aws_cognito_user_pool.this.id
    generate_secret = false
    prevent_user_existence_errors = "ENABLED"

    allowed_oauth_flows_user_pool_client = true
    allowed_oauth_flows = ["code"]
    allowed_oauth_scopes = ["openid", "email"]
    supported_identity_providers = ["COGNITO"]
    callback_urls = [for origin in var.dashboard_origins : "${origin}/"]
    logout_urls = [for origin in var.dashboard_origins : "${origin}/"]

    # The admin flow signs every call with AWS credentials, so it is not a way in for anyone else.
    # Only enabled to get tokens from the CLI while testing
    explicit_auth_flows = concat(
        ["ALLOW_REFRESH_TOKEN_AUTH"],
        var.enable_cli_auth ? ["ALLOW_ADMIN_USER_PASSWORD_AUTH"] : []
    )

    access_token_validity = 60
    id_token_validity = 60
    refresh_token_validity = 30

    token_validity_units {
        access_token = "minutes"
        id_token = "minutes"
        refresh_token = "days"
    }
}

resource "aws_cognito_user_group" "this" {
    for_each = toset(["admin", "viewer"])
    name = each.key
    user_pool_id = aws_cognito_user_pool.this.id
}

# Cognito emails a temporary password to this address
resource "aws_cognito_user" "admin" {
    user_pool_id = aws_cognito_user_pool.this.id
    username = var.alert_email
    desired_delivery_mediums = ["EMAIL"]

    attributes = {
        email = var.alert_email
        email_verified = "true"
    }
}

resource "aws_cognito_user_in_group" "admin" {
    user_pool_id = aws_cognito_user_pool.this.id
    group_name = aws_cognito_user_group.this["admin"].name
    username = aws_cognito_user.admin.username
}
