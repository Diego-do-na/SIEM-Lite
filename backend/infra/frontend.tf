# Dashboard hosting: a private S3 bucket behind CloudFront. Nothing on the bucket is public: CloudFront signs its
# requests to S3 (Origin Access Control) and the bucket policy only trusts this one distribution

locals {
    frontend_dir = "${path.module}/../../frontend"

    # What the browser needs. Everything else in frontend/ (README, .gitkeep) is not uploaded
    frontend_content_types = {
        ".html" = "text/html; charset=utf-8"
        ".js" = "text/javascript; charset=utf-8"
        ".css" = "text/css; charset=utf-8"
        ".svg" = "image/svg+xml"
        ".woff2" = "font/woff2"
        ".txt" = "text/plain; charset=utf-8"
    }

    # config.js is generated below from the outputs of this stack; config.example.js is only the template
    frontend_extensions = {
        for file in fileset(local.frontend_dir, "**") : file => lower(try(regex("\\.[^./]+$", file), ""))
    }
    frontend_files = {
        for file, extension in local.frontend_extensions : file => lookup(local.frontend_content_types, extension, "")
        if contains(keys(local.frontend_content_types), extension) && !contains(["config.js", "config.example.js"], file)
    }

    # Known before anything is created: it only depends on the Cognito domain, not on the app client (see the CSP below)
    cognito_login_url = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.aws_region}.amazoncognito.com"

    # connect-src names the API host as a pattern on purpose. The exact URL of the API would make a cycle: the API needs the
    # CloudFront domain for CORS, CloudFront needs this policy, and this policy would need the API. The page can still only
    # talk to API Gateway in this region, to its own origin and to the Cognito login domain
    frontend_csp = join("; ", [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "font-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self' https://*.execute-api.${var.aws_region}.amazonaws.com ${local.cognito_login_url}",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'"
    ])

    # The CloudFront address is added to the origins the API and Cognito accept; var.dashboard_origins keeps local development
    frontend_origin = "https://${aws_cloudfront_distribution.frontend.domain_name}"
    dashboard_origins = concat(var.dashboard_origins, [local.frontend_origin])
}

# No force_destroy: every object is managed by Terraform (below), so terraform destroy removes them one by one
resource "aws_s3_bucket" "frontend" {
    bucket = "${local.prefix}-frontend-${data.aws_caller_identity.current.account_id}"
}

resource "aws_cloudfront_origin_access_control" "frontend" {
    name = "${local.prefix}-frontend"
    description = "CloudFront signs its requests to the frontend bucket"
    origin_access_control_origin_type = "s3"
    signing_behavior = "always"
    signing_protocol = "sigv4"
}

resource "aws_cloudfront_response_headers_policy" "frontend" {
    name = "${local.prefix}-frontend-security"

    security_headers_config {
        content_security_policy {
            content_security_policy = local.frontend_csp
            override = true
        }

        strict_transport_security {
            access_control_max_age_sec = 63072000
            include_subdomains = true
            # Harmless on a cloudfront.net address (browsers only preload registered domains), required if a custom domain is added later
            preload = true
            override = true
        }

        content_type_options {
            override = true
        }

        frame_options {
            frame_option = "DENY"
            override = true
        }

        referrer_policy {
            referrer_policy = "no-referrer"
            override = true
        }
    }

    custom_headers_config {
        items {
            header = "Permissions-Policy"
            value = "camera=(), microphone=(), geolocation=()"
            override = true
        }
    }
}

# Compression comes with this managed policy. Freshness comes from Cache-Control: no-cache on every object (below), which
# CloudFront turns into its minimum of 1 second and the browser into a revalidation on each visit
data "aws_cloudfront_cache_policy" "optimized" {
    name = "Managed-CachingOptimized"
}

resource "aws_cloudfront_distribution" "frontend" {
    # checkov:skip=CKV_AWS_68:A web ACL costs a fixed monthly fee and the page holds no data (the data sits behind the API), WAF is listed as a later alternative in docs/roadmap.md
    # checkov:skip=CKV2_AWS_47:Only applies when a web ACL is attached, see CKV_AWS_68
    # checkov:skip=CKV_AWS_86:DEBT for 1.1, access logs need their own bucket, and the page serves only static files
    # checkov:skip=CKV_AWS_310:One origin (the bucket), there is nothing to fail over to. Availability, not a security control
    # checkov:skip=CKV_AWS_374:The only user may log in from anywhere, and the data stays behind the API login either way
    # checkov:skip=CKV_AWS_174:The default *.cloudfront.net certificate fixes the minimum TLS version, a custom domain with an ACM certificate is DEBT for 1.1
    # checkov:skip=CKV2_AWS_42:Same decision as CKV_AWS_174: no custom domain yet
    enabled = true
    comment = "${local.prefix} dashboard"
    default_root_object = "index.html"
    http_version = "http2and3"
    is_ipv6_enabled = true
    # North America and Europe only: the cheapest class, and the dashboard has one user
    price_class = "PriceClass_100"

    origin {
        domain_name = aws_s3_bucket.frontend.bucket_regional_domain_name
        origin_id = "frontend-bucket"
        origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
    }

    default_cache_behavior {
        target_origin_id = "frontend-bucket"
        viewer_protocol_policy = "redirect-to-https"
        allowed_methods = ["GET", "HEAD"]
        cached_methods = ["GET", "HEAD"]
        compress = true
        cache_policy_id = data.aws_cloudfront_cache_policy.optimized.id
        response_headers_policy_id = aws_cloudfront_response_headers_policy.frontend.id
    }

    restrictions {
        geo_restriction {
            restriction_type = "none"
        }
    }

    viewer_certificate {
        cloudfront_default_certificate = true
    }
}

data "aws_iam_policy_document" "frontend_bucket" {
    statement {
        sid = "AllowThisDistributionToRead"
        actions = ["s3:GetObject"]
        resources = ["${aws_s3_bucket.frontend.arn}/*"]

        principals {
            type = "Service"
            identifiers = ["cloudfront.amazonaws.com"]
        }

        condition {
            test = "StringEquals"
            variable = "AWS:SourceArn"
            values = [aws_cloudfront_distribution.frontend.arn]
        }
    }

    statement {
        sid = "DenyInsecureTransport"
        effect = "Deny"
        actions = ["s3:*"]
        resources = [aws_s3_bucket.frontend.arn, "${aws_s3_bucket.frontend.arn}/*"]

        principals {
            type = "*"
            identifiers = ["*"]
        }

        condition {
            test = "Bool"
            variable = "aws:SecureTransport"
            values = ["false"]
        }
    }
}

resource "aws_s3_bucket_policy" "frontend" {
    bucket = aws_s3_bucket.frontend.id
    policy = data.aws_iam_policy_document.frontend_bucket.json

    # S3 rejects a policy applied while the public access block is still being set up
    depends_on = [aws_s3_bucket_public_access_block.this]
}

# One object per file of frontend/. The etag makes Terraform upload it again whenever the file changes
resource "aws_s3_object" "frontend" {
    for_each = local.frontend_files

    bucket = aws_s3_bucket.frontend.id
    key = each.key
    source = "${local.frontend_dir}/${each.key}"
    etag = filemd5("${local.frontend_dir}/${each.key}")
    content_type = each.value
    cache_control = "no-cache"
}

# What config.example.js asks you to copy by hand, generated here from the outputs of the stack
resource "aws_s3_object" "frontend_config" {
    bucket = aws_s3_bucket.frontend.id
    key = "config.js"
    content_type = "text/javascript; charset=utf-8"
    cache_control = "no-cache"

    content = <<-EOT
        window.SIEM_CONFIG = {
            apiUrl: "${aws_apigatewayv2_api.this.api_endpoint}",
            clientId: "${aws_cognito_user_pool_client.dashboard.id}",
            loginUrl: "${local.cognito_login_url}",
            pollSeconds: 10,
            idleMinutes: 30
        };
    EOT
}
